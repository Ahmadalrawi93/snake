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
    now: datetime | None = None,
    ttl_seconds: int = 120,
) -> SignedWorkerTask:
    """Revalidate scope, reserve the queued job once, then sign its task envelope.

    The returned object is a message for a future authenticated transport. This
    function does not send it, start a process, or perform any network operation.
    """
    envelope = prepare_dispatch_envelope(
        db, job_id, now=now, ttl_seconds=ttl_seconds
    )
    # Validate the secret and construct the signed message before committing the
    # one-shot reservation, so a misconfigured secret cannot strand a queued job.
    signed = sign_worker_task(envelope, secret)
    reserve_task_receipt(db, envelope, now=now)
    return signed
