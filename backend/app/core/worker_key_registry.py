"""Database-backed public-key registry for worker acknowledgement verification."""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.worker_signing import ed25519_public_key_fingerprint
from app.db.models import WorkerKey


def register_worker_public_key(
    db: Session,
    *,
    worker_id: str,
    key_id: str,
    public_key_b64: str,
    created_by: int | None,
) -> WorkerKey:
    """Register a unique Ed25519 public key; private key material is never accepted."""
    fingerprint = ed25519_public_key_fingerprint(public_key_b64)
    existing_identity = db.query(WorkerKey).filter_by(
        worker_id=worker_id, key_id=key_id
    ).first()
    if existing_identity is not None:
        raise ValueError("worker key ID is already registered; use a new key ID")
    existing_fingerprint = db.query(WorkerKey).filter_by(
        fingerprint_sha256=fingerprint
    ).first()
    if existing_fingerprint is not None:
        raise ValueError("this public key is already assigned to a worker identity")

    record = WorkerKey(
        worker_id=worker_id,
        key_id=key_id,
        public_key_b64=public_key_b64,
        fingerprint_sha256=fingerprint,
        status="active",
        created_by=created_by,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def revoke_worker_public_key(
    db: Session, *, worker_id: str, key_id: str, now: datetime | None = None
) -> WorkerKey | None:
    """One-way revocation. Re-registering requires a new key ID and keypair."""
    record = db.query(WorkerKey).filter_by(
        worker_id=worker_id, key_id=key_id
    ).first()
    if record is None:
        return None
    if record.status != "active":
        raise ValueError("worker key is already revoked")
    record.status = "revoked"
    record.revoked_at = now or datetime.now(timezone.utc)
    db.commit()
    db.refresh(record)
    return record


def get_active_worker_public_key(
    db: Session, *, worker_id: str, key_id: str
) -> str | None:
    record = db.query(WorkerKey).filter_by(
        worker_id=worker_id, key_id=key_id, status="active"
    ).first()
    return record.public_key_b64 if record is not None else None
