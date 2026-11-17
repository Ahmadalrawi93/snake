"""Internal authenticated task issuance; network delivery remains deliberately disabled."""
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.worker_claims import reserve_task_receipt
from app.core.worker_dispatch import prepare_dispatch_envelope
from app.core.worker_key_registry import get_active_worker_public_key
from app.core.worker_signing import SignedWorkerTask, sign_worker_task


def issue_signed_worker_task(
    db: Session,
    job_id: int,
    *,
    backend_private_key_b64: str,
    worker_id: str,
    key_id: str,
    now: datetime | None = None,
    ttl_seconds: int = 120,
) -> SignedWorkerTask:
    """Require a registered active worker key, revalidate scope, sign, then reserve once.

    This function creates an authenticated message only. It does not open a socket,
    contact a worker, retry delivery, or enable scan execution.
    """
    if get_active_worker_public_key(db, worker_id=worker_id, key_id=key_id) is None:
        raise ValueError("worker key is not registered and active")

    envelope = prepare_dispatch_envelope(db, job_id, now=now, ttl_seconds=ttl_seconds)
    signed = sign_worker_task(
        envelope, backend_private_key_b64, worker_id=worker_id, key_id=key_id
    )
    reserve_task_receipt(
        db, envelope, worker_id=worker_id, key_id=key_id, now=now
    )
    return signed
