"""Persistence boundary for authenticated, unconfirmed worker observations."""
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.worker_key_registry import get_active_worker_public_key
from app.core.worker_observation_signing import (
    observation_batch_digest,
    verify_worker_observation_batch,
)
from app.db.models import WorkerObservationRecord, WorkerTaskReceipt
from app.schemas.worker_results import SignedWorkerObservationBatch


def store_worker_observation_batch(
    db: Session,
    signed: SignedWorkerObservationBatch,
    *,
    now: datetime | None = None,
) -> int:
    """Verify worker identity, receipt binding and signature before immutable insert.

    Returns the number of newly persisted observations. Duplicate observation IDs
    reject the entire batch; callers must roll back on any exception.
    """
    batch = signed.batch
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("current time must be timezone-aware")
    if batch.execution_enabled is not False:
        raise ValueError("worker execution must remain disabled")

    receipt = (
        db.query(WorkerTaskReceipt)
        .filter(WorkerTaskReceipt.task_id == str(batch.task_id))
        .first()
    )
    if (
        receipt is None
        or receipt.envelope_sha256 != batch.envelope_sha256
        or receipt.worker_id != batch.worker_id
        or receipt.key_id != batch.key_id
        or receipt.consumed_at is None
    ):
        raise ValueError("observation batch is not bound to a consumed task receipt")

    public_key = get_active_worker_public_key(
        db, worker_id=batch.worker_id, key_id=batch.key_id
    )
    if public_key is None or not verify_worker_observation_batch(signed, public_key):
        raise ValueError("worker observation signature is invalid or key is revoked")

    collected_at = batch.collected_at.astimezone(timezone.utc)
    if collected_at > current.astimezone(timezone.utc):
        raise ValueError("observation batch timestamp is in the future")
    if collected_at < receipt.created_at.replace(tzinfo=timezone.utc) if receipt.created_at.tzinfo is None else collected_at < receipt.created_at.astimezone(timezone.utc):
        raise ValueError("observation batch predates task issuance")

    digest = observation_batch_digest(batch)
    records = [
        WorkerObservationRecord(
            observation_id=str(item.observation_id),
            task_id=str(batch.task_id),
            worker_id=batch.worker_id,
            key_id=batch.key_id,
            envelope_sha256=batch.envelope_sha256,
            batch_sha256=digest,
            kind=item.kind,
            value=item.value,
            evidence=item.evidence,
            source=item.source,
            observed_at=item.observed_at.astimezone(timezone.utc),
            collected_at=collected_at,
            received_at=current.astimezone(timezone.utc),
            classification="unconfirmed_observation",
        )
        for item in batch.observations
    ]
    db.add_all(records)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("duplicate observation ID; batch was not stored") from exc
    return len(records)
