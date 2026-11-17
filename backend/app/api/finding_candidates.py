"""Owner-scoped persisted finding candidate API."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.api.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.core.finding_candidates import persist_finding_candidate, list_finding_candidates
from app.schemas.finding_candidates import FindingCandidateCreate, FindingCandidateRead

router = APIRouter(prefix="/api/v1")


@router.post("/analysis-runs/{analysis_run_id}/finding-candidates", response_model=FindingCandidateRead, status_code=201)
def create_finding_candidate(analysis_run_id: int, payload: FindingCandidateCreate,
    db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    try:
        record = persist_finding_candidate(db, analysis_run_id=analysis_run_id, actor=actor, payload=payload)
        db.commit()
        db.refresh(record)
        return record
    except LookupError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Analysis run not found")
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Candidate conflicts with an existing record")


@router.get("/analysis-runs/{analysis_run_id}/finding-candidates", response_model=list[FindingCandidateRead])
def read_finding_candidates(analysis_run_id: int, db: Session = Depends(get_db),
    actor: User = Depends(get_current_user)):
    try:
        return list_finding_candidates(db, analysis_run_id=analysis_run_id, actor=actor)
    except LookupError:
        raise HTTPException(status_code=404, detail="Analysis run not found")
