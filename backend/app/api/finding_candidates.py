"""Read-only owner-scoped candidate and similarity APIs."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.core.finding_candidates import list_finding_candidates
from app.core.persisted_finding_intelligence import compare_persisted_candidate
from app.schemas.finding_candidates import FindingCandidateRead
from app.schemas.finding_intelligence import CandidateSimilarityResult

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


@router.get(
    "/projects/{project_id}/finding-candidates/{candidate_id}/similarity",
    response_model=list[CandidateSimilarityResult],
)
def read_candidate_similarity(
    project_id: int, candidate_id: int, db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        return compare_persisted_candidate(
            db, project_id=project_id, candidate_id=candidate_id, actor=actor
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Project or candidate not found")
