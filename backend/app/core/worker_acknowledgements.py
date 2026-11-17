"""Verify and atomically consume Ed25519 acknowledgements against registered worker keys."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.worker_claims import consume_task_receipt
from app.core.worker_key_registry import get_active_worker_public_key
from app.core.worker_protocol import WorkerValidationResult
from app.core.worker_signing import (
    SignedWorkerValidationResult,
    verify_worker_validation_result,
)
from app.db.models import WorkerDispatchAttempt, WorkerTaskReceipt

MAX_CLOCK_SKEW = timedelta(seconds=30)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def accept_worker_acknowledgement(
    db: Session,
    signed: SignedWorkerValidationResult,
    *,
    expected_worker_id: str,
    expected_key_id: str,
    now: datetime | None = None,
) -> bool:
    current = _as_utc(now or datetime.now(timezone.utc))
    result: WorkerValidationResult = signed.result
    if not expected_worker_id or result.worker_id != expected_worker_id:
        return False
    if result.execution_enabled is not False or signed.key_id != expected_key_id:
        return False

    worker_public_key_b64 = get_active_worker_public_key(
        db, worker_id=expected_worker_id, key_id=expected_key_id
    )
    if worker_public_key_b64 is None:
        return False
    if not verify_worker_validation_result(
        signed, worker_public_key_b64,
        expected_worker_id=expected_worker_id, expected_key_id=expected_key_id,
    ):
        return False

    receipt = (
        db.query(WorkerTaskReceipt)
        .filter(WorkerTaskReceipt.task_id == str(result.task_id))
        .first()
    )
    if (
        receipt is None
        or receipt.envelope_sha256 != result.envelope_sha256
        or receipt.worker_id != expected_worker_id
        or receipt.key_id != expected_key_id
    ):
        return False

    validated_at = _as_utc(result.validated_at)
    created_at = _as_utc(receipt.created_at)
    expires_at = _as_utc(receipt.expires_at)
    if validated_at < created_at - MAX_CLOCK_SKEW:
        return False
    if validated_at > current + MAX_CLOCK_SKEW:
        return False
    if validated_at >= expires_at or current >= expires_at:
        return False

    return consume_task_receipt(
        db, str(result.task_id), result.envelope_sha256, now=current,
        acknowledgement_outcome=result.outcome,
        acknowledgement_worker_id=result.worker_id,
        acknowledgement_validated_at=validated_at,
    )



def reconcile_unknown_worker_acknowledgement(
    db: Session,
    signed: SignedWorkerValidationResult,
    *,
    expected_worker_id: str,
    expected_key_id: str,
    now: datetime | None = None,
) -> bool:
    """Atomically reconcile a late signed acknowledgement for an unknown attempt.

    The worker's validated_at must fall inside the original task validity window,
    even if the backend receives the signed acknowledgement after expiry.
    No scan execution or job completion is implied.
    """
    current = _as_utc(now or datetime.now(timezone.utc))
    result: WorkerValidationResult = signed.result
    if not expected_worker_id or result.worker_id != expected_worker_id:
        return False
    if result.execution_enabled is not False or signed.key_id != expected_key_id:
        return False

    public_key = get_active_worker_public_key(
        db, worker_id=expected_worker_id, key_id=expected_key_id
    )
    if public_key is None or not verify_worker_validation_result(
        signed, public_key,
        expected_worker_id=expected_worker_id,
        expected_key_id=expected_key_id,
    ):
        return False

    task_id = str(result.task_id)
    receipt = (
        db.query(WorkerTaskReceipt)
        .filter(WorkerTaskReceipt.task_id == task_id)
        .with_for_update()
        .first()
    )
    if (
        receipt is None
        or receipt.envelope_sha256 != result.envelope_sha256
        or receipt.worker_id != expected_worker_id
        or receipt.key_id != expected_key_id
        or receipt.consumed_at is not None
    ):
        return False

    validated_at = _as_utc(result.validated_at)
    created_at = _as_utc(receipt.created_at)
    expires_at = _as_utc(receipt.expires_at)
    if validated_at < created_at - MAX_CLOCK_SKEW:
        return False
    if validated_at >= expires_at or validated_at > current + MAX_CLOCK_SKEW:
        return False

    latest = (
        db.query(WorkerDispatchAttempt)
        .filter(WorkerDispatchAttempt.task_id == task_id)
        .order_by(WorkerDispatchAttempt.attempt_number.desc())
        .with_for_update()
        .first()
    )
    if (
        latest is None
        or latest.status != "unknown"
        or latest.worker_id != expected_worker_id
        or latest.key_id != expected_key_id
        or latest.envelope_sha256 != result.envelope_sha256
    ):
        return False

    consumed = db.execute(
        update(WorkerTaskReceipt)
        .where(
            WorkerTaskReceipt.task_id == task_id,
            WorkerTaskReceipt.envelope_sha256 == result.envelope_sha256,
            WorkerTaskReceipt.worker_id == expected_worker_id,
            WorkerTaskReceipt.key_id == expected_key_id,
            WorkerTaskReceipt.consumed_at.is_(None),
        )
        .values(
            consumed_at=current,
            acknowledgement_outcome=result.outcome,
            acknowledgement_worker_id=result.worker_id,
            acknowledgement_validated_at=validated_at,
        )
        .execution_options(synchronize_session=False)
    )
    if consumed.rowcount != 1:
        db.rollback()
        return False

    closed = db.execute(
        update(WorkerDispatchAttempt)
        .where(
            WorkerDispatchAttempt.id == latest.id,
            WorkerDispatchAttempt.status == "unknown",
        )
        .values(status="delivered", error_code=None, completed_at=current)
        .execution_options(synchronize_session=False)
    )
    if closed.rowcount != 1:
        db.rollback()
        return False
    return True
