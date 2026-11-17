"""Build analysis inputs exclusively from verified, persisted worker observations."""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.core.analysis_context import build_analysis_context
from app.core.evidence_correlation import correlate_analysis_context
from app.core.worker_observation_signing import verify_worker_observation_batch, observation_batch_digest
from app.db.models import (
    AIAnalysisRun, AnalysisRunObservationLink, Authorization, Project, ScanJob,
    ScopeSnapshot, Target, WorkerKey, WorkerObservationRecord, WorkerTaskReceipt, User,
)
from app.schemas.worker_results import SignedWorkerObservationBatch, WorkerObservation


@dataclass(frozen=True)
class PersistedAnalysisInput:
    context: object
    correlations: object
    records: tuple[WorkerObservationRecord, ...]
    provenance_sha256: str


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _canonical_hash(value) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _verify_snapshot(snapshot: ScopeSnapshot) -> bool:
    try:
        data = json.loads(snapshot.snapshot_json)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode()).hexdigest() == snapshot.sha256
    except (TypeError, ValueError):
        return False


def build_persisted_analysis_input(
    db: Session, *, project_id: int, target_id: int, actor: User,
    now: datetime | None = None,
) -> PersistedAnalysisInput:
    """Load only observations attached to acknowledged passive tasks and valid scope snapshots."""
    current = _utc(now or datetime.now(timezone.utc))
    target = db.query(Target).join(Project, Project.id == Target.project_id).filter(
        Target.id == target_id, Target.project_id == project_id, Project.owner_id == actor.id
    ).first()
    if target is None:
        raise LookupError("target not found")
    rows = (
        db.query(WorkerObservationRecord, WorkerTaskReceipt, ScanJob, ScopeSnapshot, Authorization)
        .join(WorkerTaskReceipt, WorkerTaskReceipt.task_id == WorkerObservationRecord.task_id)
        .join(ScanJob, ScanJob.id == WorkerTaskReceipt.job_id)
        .join(ScopeSnapshot, ScopeSnapshot.id == ScanJob.scope_snapshot_id)
        .join(Authorization, Authorization.id == ScopeSnapshot.authorization_id)
        .filter(
            ScanJob.project_id == project_id,
            ScanJob.target_id == target_id,
            ScanJob.profile == "passive_recon",
            ScanJob.execution_enabled.is_(False),
            WorkerTaskReceipt.consumed_at.is_not(None),
            WorkerTaskReceipt.acknowledgement_worker_id == WorkerTaskReceipt.worker_id,
            WorkerObservationRecord.envelope_sha256 == WorkerTaskReceipt.envelope_sha256,
        )
        .order_by(WorkerObservationRecord.id.asc())
        .all()
    )
    if not rows:
        raise ValueError("no acknowledged worker observations exist for this target")
    records: list[WorkerObservationRecord] = []
    provenance_items = []
    verified_batches: dict[str, tuple[str, str]] = {}
    for record, receipt, job, snapshot, authorization in rows:
        if (job.project_id != project_id or job.target_id != target_id
                or snapshot.project_id != project_id or snapshot.target_id != target_id
                or authorization.project_id != project_id
                or snapshot.authorization_id != authorization.id):
            raise ValueError("observation provenance crosses project or target boundary")
        if snapshot.status != "active" or authorization.status != "approved":
            raise ValueError("scope snapshot or authorization is no longer active")
        if not _verify_snapshot(snapshot):
            raise ValueError("scope snapshot integrity check failed")
        if snapshot.expires_at:
            expiry = datetime.fromisoformat(snapshot.expires_at.replace("Z", "+00:00"))
            if _utc(expiry) <= current:
                raise ValueError("scope authorization has expired")
        if authorization.expires_at:
            expiry = datetime.fromisoformat(authorization.expires_at.replace("Z", "+00:00"))
            if _utc(expiry) <= current:
                raise ValueError("authorization has expired")
        if authorization.starts_at:
            starts = datetime.fromisoformat(authorization.starts_at.replace("Z", "+00:00"))
            if _utc(starts) > current:
                raise ValueError("authorization is not active yet")
        if (receipt.worker_id != record.worker_id or receipt.key_id != record.key_id
                or receipt.consumed_at is None or not record.batch_payload_json
                or not record.batch_signature):
            raise ValueError("worker observation receipt binding is incomplete")
        if record.task_id not in verified_batches:
            key = db.query(WorkerKey).filter_by(
                worker_id=record.worker_id, key_id=record.key_id
            ).first()
            if key is None:
                raise ValueError("historical worker verification key is unavailable")
            signed = SignedWorkerObservationBatch.model_validate_json(json.dumps({
                "batch": json.loads(record.batch_payload_json),
                "signature": record.batch_signature,
            }))
            batch = signed.batch
            if (batch.task_id != __import__("uuid").UUID(receipt.task_id)
                    or batch.envelope_sha256 != receipt.envelope_sha256
                    or batch.worker_id != receipt.worker_id or batch.key_id != receipt.key_id
                    or observation_batch_digest(batch) != record.batch_sha256
                    or not verify_worker_observation_batch(signed, key.public_key_b64)):
                raise ValueError("stored worker observation signature or digest is invalid")
            verified_batches[record.task_id] = (record.batch_sha256, record.batch_signature)
        batch_digest, signature = verified_batches[record.task_id]
        if record.batch_sha256 != batch_digest or record.batch_signature != signature:
            raise ValueError("worker batch records are inconsistent")
        provenance_items.append({
            "observation_id": record.observation_id, "record_id": record.id,
            "task_id": record.task_id, "worker_id": record.worker_id,
            "key_id": record.key_id, "envelope_sha256": record.envelope_sha256,
            "batch_sha256": record.batch_sha256, "batch_signature": record.batch_signature,
            "scope_snapshot_id": snapshot.id, "scope_snapshot_sha256": snapshot.sha256,
            "authorization_id": authorization.id, "target_id": target_id, "project_id": project_id,
        })
        records.append(record)
    observations = [
        WorkerObservation(
            observation_id=__import__("uuid").UUID(record.observation_id),
            kind=record.kind, value=record.value, evidence=record.evidence,
            source=record.source, observed_at=_utc(record.observed_at),
        )
        for record in records
    ]
    context = build_analysis_context(observations)
    correlations = correlate_analysis_context(context)
    provenance_items.sort(key=lambda item: (item["task_id"], item["observation_id"]))
    return PersistedAnalysisInput(
        context=context, correlations=correlations, records=tuple(records),
        provenance_sha256=_canonical_hash(provenance_items),
    )


def bind_analysis_run_provenance(
    db: Session, *, run: AIAnalysisRun, project_id: int, target_id: int,
    source: PersistedAnalysisInput,
) -> None:
    """Persist immutable observation-to-run edges after the analysis result is stored."""
    run.provenance_sha256 = source.provenance_sha256
    run.source_observation_count = len(source.records)
    by_id = {record.id: record for record in source.records}
    for record in source.records:
        receipt, job, snapshot, authorization = (
            db.query(WorkerTaskReceipt, ScanJob, ScopeSnapshot, Authorization)
            .join(ScanJob, ScanJob.id == WorkerTaskReceipt.job_id)
            .join(ScopeSnapshot, ScopeSnapshot.id == ScanJob.scope_snapshot_id)
            .join(Authorization, Authorization.id == ScopeSnapshot.authorization_id)
            .filter(WorkerTaskReceipt.task_id == record.task_id).one()
        )
        db.add(AnalysisRunObservationLink(
            analysis_run_id=run.id, observation_record_id=record.id,
            project_id=project_id, target_id=target_id, task_id=record.task_id,
            worker_id=record.worker_id, key_id=record.key_id,
            envelope_sha256=record.envelope_sha256, batch_sha256=record.batch_sha256,
            batch_signature=record.batch_signature, scope_snapshot_id=snapshot.id,
            scope_snapshot_sha256=snapshot.sha256, authorization_id=authorization.id,
        ))
    db.flush()
