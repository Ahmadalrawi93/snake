"""Internal authenticated message preparation; deliberately no network transport."""
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.worker_dispatch import prepare_dispatch_envelope
from app.core.worker_claims import reserve_task_receipt
from app.core.worker_signing import SignedWorkerTask, sign_worker_task


def issue_signed_worker_task(
    db: Session,
    job_id: int,
    *,
    secret: str,
    worker_id: str,
    key_id: str,
    now: datetime | None = None,
    ttl_seconds: int = 120,
) -> SignedWorkerTask:
    """Revalidate scope, sign for one worker, then reserve the queued job exactly once.

    The caller must select secret/key_id from a trusted per-worker secret source.
    This function does not send the message, start a process, or perform network I/O.
    """
    envelope = prepare_dispatch_envelope(db, job_id, now=now, ttl_seconds=ttl_seconds)
    # Sign before reservation: invalid configuration must not strand the queued job.
    signed = sign_worker_task(
        envelope, secret, worker_id=worker_id, key_id=key_id
    )
    reserve_task_receipt(db, envelope, now=now)
    return signed
