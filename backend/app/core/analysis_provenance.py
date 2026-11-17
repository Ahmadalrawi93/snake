"""Build analysis inputs exclusively from verified, persisted worker observations."""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from uuid import UUID
from datetime import datetime, timezone
from app.core.scope_policy import ScopePolicy
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


def _record_matches_batch(record: WorkerObservationRecord, batch) -> bool:
    item = next((entry for entry in batch.observations if str(entry.observation_id) == record.observation_id), None)
    canonical_payload = json.dumps(batch.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return bool(
        item is not None
        and record.batch_payload_json == canonical_payload
        and item.kind == record.kind
        and item.value == record.value
        and item.evidence == record.evidence
        and item.source == record.source
        and _utc(item.observed_at) == _utc(record.observed_at)
    )


def _verify_snapshot(snapshot: ScopeSnapshot, authorization: Authorization, *, require_current_rules: bool = True) -> bool:
    try:
        data = json.loads(snapshot.snapshot_json)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if hashlib.sha256(canonical.encode()).hexdigest() != snapshot.sha256:
            return False
        if (data.get("project_id") != snapshot.project_id
                or data.get("target_id") != snapshot.target_id
                or data.get("authorization_id") != snapshot.authorization_id
                or data.get("execution_enabled") is not False
                or data.get("authorization_status") != "approved"):
            return False
        rules = data.get("approved_scope_rules")
        if not isinstance(rules, list):
            return False
        if require_current_rules:
            current_rules = json.loads(authorization.scope_rules or "[]")
            if sorted(rules) != sorted(current_rules):
                return False
        target_url = data.get("target")
        decision = ScopePolicy(rules).check_url(target_url if isinstance(target_url, str) else "")
        return bool(decision.allowed and decision.hostname == data.get("hostname"))
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
    verified_batches: dict[str, tuple[str, str, object]] = {}
    for record, receipt, job, snapshot, authorization in rows:
        if (job.project_id != project_id or job.target_id != target_id
                or snapshot.project_id != project_id or snapshot.target_id != target_id
                or authorization.project_id != project_id
                or snapshot.authorization_id != authorization.id):
            raise ValueError("observation provenance crosses project or target boundary")
        if snapshot.status != "active" or authorization.status != "approved":
            raise ValueError("scope snapshot or authorization is no longer active")
        if not _verify_snapshot(snapshot, authorization):
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
            if key is None or key.status != "active":
                raise ValueError("worker verification key is unavailable or revoked for new analysis")
            signed = SignedWorkerObservationBatch.model_validate_json(json.dumps({
                "batch": json.loads(record.batch_payload_json),
                "signature": record.batch_signature,
            }))
            batch = signed.batch
            if (_utc(batch.collected_at) < _utc(receipt.created_at)
                    or _utc(batch.collected_at) >= _utc(receipt.expires_at)
                    or _utc(batch.collected_at) > current):
                raise ValueError("signed observation batch timestamp is outside task validity")
            if (receipt.acknowledgement_outcome != "accepted"
                    or receipt.acknowledgement_worker_id != receipt.worker_id):
                raise ValueError("worker task was not acknowledged as accepted")
            if (batch.task_id != UUID(receipt.task_id)
                    or batch.envelope_sha256 != receipt.envelope_sha256
                    or batch.worker_id != receipt.worker_id or batch.key_id != receipt.key_id
                    or observation_batch_digest(batch) != record.batch_sha256
                    or not verify_worker_observation_batch(signed, key.public_key_b64)):
                raise ValueError("stored worker observation signature or digest is invalid")
            verified_batches[record.task_id] = (record.batch_sha256, record.batch_signature, batch)
        batch_digest, signature, verified_batch = verified_batches[record.task_id]
        if (record.batch_sha256 != batch_digest or record.batch_signature != signature
                or not _record_matches_batch(record, verified_batch)):
            raise ValueError("worker observation row does not match its signed batch")
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
            observation_id=UUID(record.observation_id),
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



def load_verified_analysis_run_context(db: Session, *, run: AIAnalysisRun):
    """Rebuild context from immutable run links and re-verify stored worker signatures."""
    joined = (
        db.query(AnalysisRunObservationLink, WorkerObservationRecord, ScopeSnapshot, Authorization, WorkerTaskReceipt, ScanJob)
        .join(WorkerObservationRecord, WorkerObservationRecord.id == AnalysisRunObservationLink.observation_record_id)
        .join(WorkerTaskReceipt, WorkerTaskReceipt.task_id == WorkerObservationRecord.task_id)
        .join(ScanJob, ScanJob.id == WorkerTaskReceipt.job_id)
        .join(ScopeSnapshot, ScopeSnapshot.id == AnalysisRunObservationLink.scope_snapshot_id)
        .join(Authorization, Authorization.id == AnalysisRunObservationLink.authorization_id)
        .filter(AnalysisRunObservationLink.analysis_run_id == run.id)
        .order_by(AnalysisRunObservationLink.id.asc())
        .all()
    )
    if not joined or len(joined) != run.source_observation_count:
        raise ValueError("analysis run observation provenance is incomplete")
    batch_checks = {}
    records = []
    provenance_items = []
    for link, record, snapshot, authorization, receipt, job in joined:
        if (job.project_id != run.project_id or job.target_id != run.target_id
                or job.scope_snapshot_id != snapshot.id or job.profile != "passive_recon"
                or job.execution_enabled is not False
                or receipt.worker_id != record.worker_id or receipt.key_id != record.key_id
                or receipt.envelope_sha256 != record.envelope_sha256
                or receipt.acknowledgement_outcome != "accepted"
                or receipt.acknowledgement_worker_id != record.worker_id
                or receipt.consumed_at is None
                or snapshot.project_id != run.project_id or snapshot.target_id != run.target_id
                or link.project_id != run.project_id or link.target_id != run.target_id
                or link.task_id != record.task_id or link.worker_id != record.worker_id
                or link.key_id != record.key_id or link.envelope_sha256 != record.envelope_sha256
                or link.batch_sha256 != record.batch_sha256
                or link.batch_signature != record.batch_signature
                or link.scope_snapshot_sha256 != snapshot.sha256
                or link.authorization_id != snapshot.authorization_id
                or authorization.project_id != run.project_id):
            raise ValueError("analysis run provenance link integrity check failed")
        if not _verify_snapshot(snapshot, authorization, require_current_rules=False):
            raise ValueError("linked scope snapshot integrity check failed")
        if record.task_id not in batch_checks:
            key = db.query(WorkerKey).filter_by(worker_id=record.worker_id, key_id=record.key_id).first()
            if key is None:
                raise ValueError("historical worker verification key is unavailable")
            signed = SignedWorkerObservationBatch.model_validate_json(json.dumps({
                "batch": json.loads(record.batch_payload_json), "signature": record.batch_signature,
            }))
            if (observation_batch_digest(signed.batch) != record.batch_sha256
                    or signed.batch.task_id != UUID(record.task_id)
                    or signed.batch.envelope_sha256 != record.envelope_sha256
                    or signed.batch.worker_id != record.worker_id or signed.batch.key_id != record.key_id
                    or not verify_worker_observation_batch(signed, key.public_key_b64)):
                raise ValueError("linked worker batch signature is invalid")
            batch_checks[record.task_id] = signed.batch
        if not _record_matches_batch(record, batch_checks[record.task_id]):
            raise ValueError("linked observation row does not match its signed batch")
        records.append(record)
        provenance_items.append({
            "observation_id": record.observation_id, "record_id": record.id,
            "task_id": record.task_id, "worker_id": record.worker_id,
            "key_id": record.key_id, "envelope_sha256": record.envelope_sha256,
            "batch_sha256": record.batch_sha256, "batch_signature": record.batch_signature,
            "scope_snapshot_id": snapshot.id, "scope_snapshot_sha256": snapshot.sha256,
            "authorization_id": authorization.id, "target_id": link.target_id,
            "project_id": link.project_id,
        })
    provenance_items.sort(key=lambda item: (item["task_id"], item["observation_id"]))
    digest = _canonical_hash(provenance_items)
    if digest != run.provenance_sha256:
        raise ValueError("analysis run provenance digest mismatch")
    observations = [
        WorkerObservation(
            observation_id=UUID(record.observation_id), kind=record.kind,
            value=record.value, evidence=record.evidence, source=record.source,
            observed_at=_utc(record.observed_at),
        ) for record in records
    ]
    context = build_analysis_context(observations)
    if _canonical_hash(context.model_dump(mode="json")) != run.context_sha256:
        raise ValueError("persisted analysis context no longer matches linked worker observations")
    return context, correlate_analysis_context(context)
