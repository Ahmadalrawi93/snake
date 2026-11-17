"""Owner-scoped human decisions for finding candidates."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.core.finding_decisions import (
    record_human_finding_decision, list_human_finding_decisions,
)
from app.schemas.finding_decisions import HumanFindingDecisionCreate, HumanFindingDecisionRead

router = APIRouter(prefix="/api/v1")


@router.post(
    "/analysis-runs/{analysis_run_id}/finding-decisions",
    response_model=HumanFindingDecisionRead,
    status_code=201,
)
def create_finding_decision(
    analysis_run_id: int,
    payload: HumanFindingDecisionCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        record = record_human_finding_decision(
            db, analysis_run_id=analysis_run_id, actor=actor, payload=payload
        )
        db.commit()
        db.refresh(record)
        return record
    except LookupError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Analysis run not found")
    except ValueError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Reviewer has already decided on this candidate")
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Decision conflicts with an existing review")


@router.get(
    "/analysis-runs/{analysis_run_id}/finding-decisions",
    response_model=list[HumanFindingDecisionRead],
)
def read_finding_decisions(
    analysis_run_id: int,
    candidate_fingerprint: str = Query(pattern=r"^[a-f0-9]{64}$"),
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        return list_human_finding_decisions(
            db, analysis_run_id=analysis_run_id,
            candidate_fingerprint=candidate_fingerprint, actor=actor,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Analysis run not found")
