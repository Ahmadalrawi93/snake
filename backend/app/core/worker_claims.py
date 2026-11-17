"""Internal atomic reservation and one-time task receipt primitives.

These functions are intentionally not exposed as HTTP routes and do not execute work.
A successful receipt consume is an acknowledgement/replay barrier only.
"""
from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.worker_protocol import WorkerTaskEnvelope, ensure_not_expired
from app.core.worker_signing import worker_task_digest
from app.db.models import ScanJob, WorkerTaskReceipt


def envelope_digest(envelope: WorkerTaskEnvelope) -> str:
    return worker_task_digest(envelope)


def reserve_task_receipt(
    db: Session,
    envelope: WorkerTaskEnvelope,
    *,
    now: datetime | None = None,
) -> WorkerTaskReceipt:
    """Atomically reserve one queued job and persist its unique task receipt.

    A conditional UPDATE is the concurrency gate. Unique task_id and job_id
    constraints are a second durable barrier against duplicate issuance.
    """
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("current time must be timezone-aware")
    ensure_not_expired(envelope, now=current)
    if envelope.execution_enabled is not False:
        raise ValueError("worker execution is disabled")

    try:
        result = db.execute(
            update(ScanJob)
            .where(
                ScanJob.id == envelope.job_id,
                ScanJob.status == "queued",
                ScanJob.execution_enabled.is_(False),
                ScanJob.profile == envelope.profile,
                ScanJob.scope_snapshot_id == envelope.scope_snapshot_id,
            )
            .values(status="dispatch_reserved", updated_at=current)
        )
        if result.rowcount != 1:
            db.rollback()
            raise ValueError("job is no longer eligible for atomic reservation")

        receipt = WorkerTaskReceipt(
            task_id=str(envelope.task_id),
            job_id=envelope.job_id,
            envelope_sha256=envelope_digest(envelope),
            expires_at=envelope.expires_at.astimezone(timezone.utc),
            consumed_at=None,
            created_at=current.astimezone(timezone.utc),
        )
        db.add(receipt)
        db.flush()
        db.commit()
        db.refresh(receipt)
        return receipt
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("task or job already has a durable receipt") from exc
    except Exception:
        db.rollback()
        raise


def consume_task_receipt(
    db: Session,
    task_id: str,
    expected_envelope_sha256: str,
    *,
    now: datetime | None = None,
) -> bool:
    """Consume a matching unexpired receipt exactly once with a conditional UPDATE."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("current time must be timezone-aware")
    if len(expected_envelope_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in expected_envelope_sha256
    ):
        return False

    result = db.execute(
        update(WorkerTaskReceipt)
        .where(
            WorkerTaskReceipt.task_id == task_id,
            WorkerTaskReceipt.envelope_sha256 == expected_envelope_sha256,
            WorkerTaskReceipt.consumed_at.is_(None),
            WorkerTaskReceipt.expires_at > current.astimezone(timezone.utc),
        )
        .values(consumed_at=current.astimezone(timezone.utc))
    )
    if result.rowcount != 1:
        db.rollback()
        return False
    db.commit()
    return True
