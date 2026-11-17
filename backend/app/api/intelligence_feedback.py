"""Owner-scoped read-only human feedback profile."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.intelligence_feedback import build_intelligence_feedback_profile
from app.db.database import get_db
from app.db.models import User
from app.schemas.intelligence_feedback import IntelligenceFeedbackProfile

router = APIRouter(prefix="/api/v1")


@router.get(
    "/projects/{project_id}/intelligence-feedback",
    response_model=IntelligenceFeedbackProfile,
)
def read_intelligence_feedback(
    project_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        return build_intelligence_feedback_profile(db, project_id=project_id, actor=actor)
    except LookupError:
        raise HTTPException(status_code=404, detail="Project not found")
