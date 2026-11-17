"""Owner-scoped, on-demand report draft generation."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.persisted_finding_report import build_persisted_candidate_report
from app.db.database import get_db
from app.db.models import User
from app.schemas.finding_report import FindingReportPreview

router = APIRouter(prefix="/api/v1")


@router.post(
    "/finding-candidates/{candidate_id}/report-draft",
    response_model=FindingReportPreview,
)
def create_candidate_report_draft(
    candidate_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        report, markdown = build_persisted_candidate_report(
            db, candidate_id=candidate_id, actor=actor
        )
        return {"report": report, "markdown": markdown}
    except LookupError:
        raise HTTPException(status_code=404, detail="Candidate not found")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
