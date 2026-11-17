from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.api.dependencies import require_admin
from app.db.database import get_db
from app.db.models import Authorization, AuditEvent, User

router = APIRouter(prefix="/api/v1/admin", tags=["administration"])

class AuthorizationReview(BaseModel):
    decision: Literal["approved", "rejected"]
    review_notes: str = Field(min_length=3, max_length=4000)
    scope_rules: list[str] = Field(default_factory=list, max_length=100)

@router.get("/authorizations/pending")
def pending_authorizations(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rows = db.query(Authorization).filter_by(status="pending").order_by(Authorization.created_at.asc()).all()
    return [{
        "id": row.id,
        "project_id": row.project_id,
        "reference": row.reference,
        "starts_at": row.starts_at,
        "expires_at": row.expires_at,
        "notes": row.notes,
        "created_at": row.created_at,
    } for row in rows]

@router.post("/authorizations/{authorization_id}/review")
def review_authorization(
    authorization_id: int,
    payload: AuthorizationReview,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    record = db.get(Authorization, authorization_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Authorization record not found")
    if record.status != "pending":
        raise HTTPException(status_code=409, detail="Only pending records can be reviewed")
    if payload.decision == "approved" and not payload.scope_rules:
        raise HTTPException(status_code=422, detail="At least one explicit hostname scope rule is required")
    if payload.decision == "approved":
        from app.core.scope_policy import normalize_host
        normalized_rules = []
        for rule in payload.scope_rules:
            try:
                if rule.startswith("*."):
                    suffix = normalize_host(rule[2:])
                    if "." not in suffix:
                        raise ValueError("Wildcard suffix must contain at least two labels")
                    normalized_rules.append("*." + suffix)
                else:
                    normalized_rules.append(normalize_host(rule))
            except ValueError:
                raise HTTPException(status_code=422, detail=f"Invalid scope rule: {rule}")
        record.scope_rules = __import__("json").dumps(sorted(set(normalized_rules)))
    record.status = payload.decision
    db.add(AuditEvent(
        actor_user_id=admin.id,
        action=f"authorization.{payload.decision}",
        resource_type="authorization",
        resource_id=str(record.id),
        details=payload.review_notes + ("; scope=" + record.scope_rules if payload.decision == "approved" else ""),
    ))
    db.commit()
    db.refresh(record)
    return {"id": record.id, "status": record.status, "review_notes": payload.review_notes}

@router.post("/scope-snapshots/{snapshot_id}/revoke")
def revoke_scope_snapshot(
    snapshot_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from datetime import datetime, timezone
    from app.db.models import ScopeSnapshot
    row = db.get(ScopeSnapshot, snapshot_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scope snapshot not found")
    if row.status != "active":
        raise HTTPException(status_code=409, detail="Only active snapshots can be revoked")
    row.status = "revoked"
    row.revoked_at = datetime.now(timezone.utc)
    db.add(AuditEvent(
        actor_user_id=admin.id,
        action="scope_snapshot.revoked",
        resource_type="scope_snapshot",
        resource_id=str(row.id),
        details=f"sha256={row.sha256}",
    ))
    db.commit()
    return {"id": row.id, "status": row.status}


class WorkerPublicKeyCreate(BaseModel):
    key_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9._-]+$")
    public_key_b64: str = Field(min_length=20, max_length=2048)


@router.get("/workers/keys")
def list_worker_keys(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from app.db.models import WorkerKey
    rows = db.query(WorkerKey).order_by(WorkerKey.worker_id, WorkerKey.created_at).all()
    return [{
        "worker_id": row.worker_id,
        "key_id": row.key_id,
        "fingerprint_sha256": row.fingerprint_sha256,
        "status": row.status,
        "created_at": row.created_at,
        "revoked_at": row.revoked_at,
    } for row in rows]


@router.post("/workers/{worker_id}/keys", status_code=201)
def register_worker_key(
    worker_id: str,
    payload: WorkerPublicKeyCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from fastapi import Path
    from app.core.worker_key_registry import register_worker_public_key
    from app.core.worker_signing import ed25519_public_key_fingerprint

    if not __import__("re").fullmatch(r"[a-zA-Z0-9._-]{1,128}", worker_id):
        raise HTTPException(status_code=422, detail="Invalid worker ID")
    try:
        fingerprint = ed25519_public_key_fingerprint(payload.public_key_b64)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    try:
        row = register_worker_public_key(
            db,
            worker_id=worker_id,
            key_id=payload.key_id,
            public_key_b64=payload.public_key_b64,
            created_by=admin.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    db.add(AuditEvent(
        actor_user_id=admin.id,
        action="worker_key.registered",
        resource_type="worker_key",
        resource_id=f"{worker_id}:{payload.key_id}",
        details=f"fingerprint_sha256={fingerprint}",
    ))
    db.commit()
    return {
        "worker_id": row.worker_id,
        "key_id": row.key_id,
        "fingerprint_sha256": row.fingerprint_sha256,
        "status": row.status,
    }


@router.post("/workers/{worker_id}/keys/{key_id}/revoke")
def revoke_worker_key(
    worker_id: str,
    key_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    from app.core.worker_key_registry import revoke_worker_public_key

    if not __import__("re").fullmatch(r"[a-zA-Z0-9._-]{1,128}", worker_id):
        raise HTTPException(status_code=422, detail="Invalid worker ID")
    if not __import__("re").fullmatch(r"[a-zA-Z0-9._-]{1,128}", key_id):
        raise HTTPException(status_code=422, detail="Invalid key ID")
    try:
        row = revoke_worker_public_key(db, worker_id=worker_id, key_id=key_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if row is None:
        raise HTTPException(status_code=404, detail="Worker key not found")
    db.add(AuditEvent(
        actor_user_id=admin.id,
        action="worker_key.revoked",
        resource_type="worker_key",
        resource_id=f"{worker_id}:{key_id}",
        details=f"fingerprint_sha256={row.fingerprint_sha256}",
    ))
    db.commit()
    return {"worker_id": row.worker_id, "key_id": row.key_id, "status": row.status}
