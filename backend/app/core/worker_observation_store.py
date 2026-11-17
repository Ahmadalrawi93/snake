"""Persistence boundary for authenticated, idempotent worker observation batches."""
from datetime import datetime, timezone
import json

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.worker_key_registry import get_active_worker_public_key
from app.core.worker_observation_signing import observation_batch_digest, verify_worker_observation_batch
from app.db.models import WorkerObservationBatchReceipt, WorkerObservationRecord, WorkerTaskReceipt
from app.schemas.worker_results import SignedWorkerObservationBatch


def store_worker_observation_batch(db: Session, signed: SignedWorkerObservationBatch, *, now: datetime | None = None) -> int:
    """Persist one signed batch atomically; exact retries return the original count."""
    batch = signed.batch
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("current time must be timezone-aware")
    if batch.execution_enabled is not False:
        raise ValueError("worker execution must remain disabled")
    receipt = db.scalar(select(WorkerTaskReceipt).where(WorkerTaskReceipt.task_id == str(batch.task_id)))
    if (receipt is None or receipt.envelope_sha256 != batch.envelope_sha256
        or receipt.worker_id != batch.worker_id or receipt.key_id != batch.key_id
        or receipt.consumed_at is None or receipt.acknowledgement_outcome != "accepted"
        or receipt.acknowledgement_worker_id != batch.worker_id):
        raise ValueError("observation batch is not bound to a consumed task receipt")
    public_key = get_active_worker_public_key(db, worker_id=batch.worker_id, key_id=batch.key_id)
    if public_key is None or not verify_worker_observation_batch(signed, public_key):
        raise ValueError("worker observation signature is invalid or key is revoked")
    collected_at = batch.collected_at.astimezone(timezone.utc)
    current_utc = current.astimezone(timezone.utc)
    issued_at = receipt.created_at.replace(tzinfo=timezone.utc) if receipt.created_at.tzinfo is None else receipt.created_at.astimezone(timezone.utc)
    expires_at = receipt.expires_at.replace(tzinfo=timezone.utc) if receipt.expires_at.tzinfo is None else receipt.expires_at.astimezone(timezone.utc)
    if collected_at > current_utc:
        raise ValueError("observation batch timestamp is in the future")
    if collected_at < issued_at:
        raise ValueError("observation batch predates task issuance")
    if collected_at >= expires_at:
        raise ValueError("observation batch was collected after task expiry")
    digest = observation_batch_digest(batch)
    existing = db.scalar(select(WorkerObservationBatchReceipt).where(WorkerObservationBatchReceipt.task_id == str(batch.task_id)))
    if existing is not None:
        identity = (existing.batch_sha256, existing.worker_id, existing.key_id, existing.envelope_sha256, existing.signature)
        incoming = (digest, batch.worker_id, batch.key_id, batch.envelope_sha256, signed.signature)
        if identity != incoming:
            raise ValueError("task already has a different immutable observation batch")
        return existing.observation_count
    payload_json = json.dumps(batch.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    records = [WorkerObservationRecord(
        observation_id=str(item.observation_id), task_id=str(batch.task_id), worker_id=batch.worker_id,
        key_id=batch.key_id, envelope_sha256=batch.envelope_sha256, batch_sha256=digest,
        batch_signature=signed.signature, batch_payload_json=payload_json, kind=item.kind,
        value=item.value, evidence=item.evidence, source=item.source,
        observed_at=item.observed_at.astimezone(timezone.utc), collected_at=collected_at,
        received_at=current_utc, classification="unconfirmed_observation",
    ) for item in batch.observations]
    batch_receipt = WorkerObservationBatchReceipt(
        task_id=str(batch.task_id), worker_id=batch.worker_id, key_id=batch.key_id,
        envelope_sha256=batch.envelope_sha256, batch_sha256=digest, signature=signed.signature,
        observation_count=len(records), received_at=current_utc,
    )
    try:
        with db.begin_nested():
            db.add(batch_receipt)
            db.add_all(records)
            db.flush()
    except IntegrityError as exc:
        raise ValueError("duplicate batch task or observation ID; batch was not stored") from exc
    return len(records)
