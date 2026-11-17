"""Internal Ed25519-authenticated message preparation; no network transport."""
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.worker_claims import reserve_task_receipt
from app.core.worker_dispatch import prepare_dispatch_envelope
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
    """Revalidate scope, sign for a worker, then reserve the queued job once."""
    envelope = prepare_dispatch_envelope(db, job_id, now=now, ttl_seconds=ttl_seconds)
    signed = sign_worker_task(
        envelope, backend_private_key_b64, worker_id=worker_id, key_id=key_id
    )
    reserve_task_receipt(db, envelope, now=now)
    return signed
