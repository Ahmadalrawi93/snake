"""Verify and atomically consume Ed25519 acknowledgements against registered worker keys."""
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.worker_claims import consume_task_receipt
from app.core.worker_key_registry import get_active_worker_public_key
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
    if receipt is None or receipt.envelope_sha256 != result.envelope_sha256:
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
