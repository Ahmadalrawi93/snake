"""Verify and atomically consume signed worker validation acknowledgements.

This module records metadata validation only. It never marks a scan complete and
never enables execution.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.worker_claims import consume_task_receipt
from app.core.worker_protocol import WorkerValidationResult
from app.core.worker_signing import (
    SignedWorkerValidationResult,
    verify_worker_validation_result,
)
from app.db.models import WorkerTaskReceipt

MAX_CLOCK_SKEW = timedelta(seconds=30)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def accept_worker_acknowledgement(
    db: Session,
    signed: SignedWorkerValidationResult,
    *,
    secret: str,
    expected_worker_id: str,
    now: datetime | None = None,
) -> bool:
    """Authenticate, bind, and consume a validation acknowledgement exactly once.

    A valid HMAC alone is insufficient: task ID, envelope digest, worker identity,
    issue/expiry window, and the durable unconsumed receipt must all match.
    """
    current = _as_utc(now or datetime.now(timezone.utc))
    result: WorkerValidationResult = signed.result

    if not expected_worker_id or result.worker_id != expected_worker_id:
        return False
    if result.execution_enabled is not False:
        return False
    try:
        if not verify_worker_validation_result(signed, secret):
            return False
    except ValueError:
        return False

    receipt = (
        db.query(WorkerTaskReceipt)
        .filter(WorkerTaskReceipt.task_id == str(result.task_id))
        .first()
    )
    if receipt is None:
        return False
    if receipt.envelope_sha256 != result.envelope_sha256:
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
        db,
        str(result.task_id),
        result.envelope_sha256,
        now=current,
        acknowledgement_outcome=result.outcome,
        acknowledgement_worker_id=result.worker_id,
        acknowledgement_validated_at=validated_at,
    )
