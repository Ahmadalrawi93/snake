"""Read-only owner-scoped API for server-persisted finding candidates."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.core.finding_candidates import list_finding_candidates
from app.schemas.finding_candidates import FindingCandidateRead

router = APIRouter(prefix="/api/v1")


@router.get(
    "/analysis-runs/{analysis_run_id}/finding-candidates",
    response_model=list[FindingCandidateRead],
)
def read_finding_candidates(
    analysis_run_id: int, db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        return list_finding_candidates(db, analysis_run_id=analysis_run_id, actor=actor)
    except LookupError:
        raise HTTPException(status_code=404, detail="Analysis run not found")
