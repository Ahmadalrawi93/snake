"""Authenticated API for immutable candidate impact assessments."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.persisted_finding_impact import (
    create_persisted_finding_impact, list_persisted_finding_impacts,
)
from app.db.database import get_db
from app.db.models import User
from app.schemas.finding_impact_persistence import (
    FindingImpactAssessmentCreate, FindingImpactAssessmentRead,
)

router = APIRouter(prefix="/api/v1")


@router.post(
    "/finding-candidates/{candidate_id}/impact-assessments",
    response_model=FindingImpactAssessmentRead,
    status_code=201,
)
def create_finding_impact_assessment(
    candidate_id: int,
    payload: FindingImpactAssessmentCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        result = create_persisted_finding_impact(
            db, candidate_id=candidate_id, actor=actor, claims=payload.claims,
        )
        db.commit()
        return result
    except LookupError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Candidate not found")
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Impact assessment conflicts with an existing record")


@router.get(
    "/finding-candidates/{candidate_id}/impact-assessments",
    response_model=list[FindingImpactAssessmentRead],
)
def read_finding_impact_assessments(
    candidate_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        return list_persisted_finding_impacts(
            db, candidate_id=candidate_id, actor=actor,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Candidate not found")
