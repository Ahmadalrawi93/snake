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
    record.status = payload.decision
    db.add(AuditEvent(
        actor_user_id=admin.id,
        action=f"authorization.{payload.decision}",
        resource_type="authorization",
        resource_id=str(record.id),
        details=payload.review_notes,
    ))
    db.commit()
    db.refresh(record)
    return {"id": record.id, "status": record.status, "review_notes": payload.review_notes}
