"""Durable dispatch-attempt state machine; no network I/O is performed here."""
import re
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import WorkerDispatchAttempt, WorkerKey, WorkerTaskReceipt

AttemptOutcome = Literal["delivered", "failed", "unknown"]


def begin_dispatch_attempt(
    db: Session,
    *,
    task_id: str,
    worker_id: str,
    key_id: str,
    envelope_sha256: str,
    now: datetime | None = None,
) -> WorkerDispatchAttempt:
    """Persist a delivery attempt before I/O; retry only after definite failure.

    Retries reuse the exact signed task ID and envelope. Unknown outcomes must be
    reconciled manually; they are never retried automatically.
    """
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("current time must be timezone-aware")
    if not re.fullmatch(r"[0-9a-f]{64}", envelope_sha256):
        raise ValueError("invalid envelope digest")
    receipt = db.query(WorkerTaskReceipt).filter_by(task_id=task_id).with_for_update().first()
    if receipt is None or receipt.envelope_sha256 != envelope_sha256:
        raise ValueError("task receipt or digest not found")
    if receipt.worker_id != worker_id or receipt.key_id != key_id:
        raise ValueError("worker identity does not match signed task receipt")
    if receipt.consumed_at is not None:
        raise ValueError("task receipt already consumed")
    receipt_expiry = receipt.expires_at
    if receipt_expiry.tzinfo is None:
        receipt_expiry = receipt_expiry.replace(tzinfo=timezone.utc)
    if receipt_expiry <= current.astimezone(timezone.utc):
        raise ValueError("task receipt expired")
    key = db.query(WorkerKey).filter_by(
        worker_id=worker_id, key_id=key_id, status="active"
    ).first()
    if key is None:
        raise ValueError("worker key is not registered and active")

    latest = db.query(WorkerDispatchAttempt).filter_by(task_id=task_id).order_by(
        WorkerDispatchAttempt.attempt_number.desc()
    ).first()
    if latest is not None and latest.status != "failed":
        raise ValueError("previous attempt is not confirmed failed")
    number = 1 if latest is None else latest.attempt_number + 1
    attempt = WorkerDispatchAttempt(
        task_id=task_id,
        attempt_number=number,
        worker_id=worker_id,
        key_id=key_id,
        envelope_sha256=envelope_sha256,
        status="started",
        started_at=current.astimezone(timezone.utc),
    )
    try:
        db.add(attempt)
        db.commit()
        db.refresh(attempt)
        return attempt
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("dispatch attempt already exists; concurrent dispatch denied") from exc


def finish_dispatch_attempt(
    db: Session,
    attempt_id: int,
    outcome: AttemptOutcome,
    *,
    error_code: str | None = None,
    now: datetime | None = None,
) -> bool:
    """Close a started attempt exactly once with a conservative delivery outcome."""
    if outcome not in ("delivered", "failed", "unknown"):
        raise ValueError("invalid dispatch outcome")
    if error_code is not None and not re.fullmatch(r"[a-z0-9_.-]{1,80}", error_code):
        raise ValueError("invalid error code")
    if outcome == "delivered" and error_code is not None:
        raise ValueError("delivered outcome cannot include an error code")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("current time must be timezone-aware")
    result = db.execute(
        update(WorkerDispatchAttempt)
        .where(
            WorkerDispatchAttempt.id == attempt_id,
            WorkerDispatchAttempt.status == "started",
        )
        .values(
            status=outcome,
            error_code=error_code,
            completed_at=current.astimezone(timezone.utc),
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        return False
    db.commit()
    return True
