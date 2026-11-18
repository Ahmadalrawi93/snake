"""Owner-scoped human evaluation endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import AIAnalysisEvaluation, Project, User
from app.core.analysis_evaluation import record_human_evaluation, get_project_evaluation_metrics
from app.schemas.analysis_evaluations import (
    AnalysisEvaluationCreate, AnalysisEvaluationMetrics, AnalysisEvaluationRead,
)

router = APIRouter(prefix="/api/v1")


@router.post("/analysis-runs/{analysis_run_id}/evaluations", response_model=AnalysisEvaluationRead, status_code=201)
def create_evaluation(
    analysis_run_id: int,
    payload: AnalysisEvaluationCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        record = record_human_evaluation(db, analysis_run_id=analysis_run_id, actor=actor, payload=payload)
        db.commit()
        db.refresh(record)
        return record
    except LookupError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Analysis run not found")
    except ValueError:
        db.rollback()
        raise HTTPException(status_code=409, detail="This reviewer has already evaluated the analysis run")


@router.get("/projects/{project_id}/analysis-evaluation-metrics", response_model=AnalysisEvaluationMetrics)
def read_evaluation_metrics(
    project_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        return get_project_evaluation_metrics(db, project_id=project_id, actor=actor)
    except LookupError:
        raise HTTPException(status_code=404, detail="Project not found")


@router.get("/analysis-runs/{analysis_run_id}/evaluations", response_model=list[AnalysisEvaluationRead])
def list_evaluations(
    analysis_run_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    from app.db.models import AIAnalysisRun
    owned_run = db.query(AIAnalysisRun.id, AIAnalysisRun.project_id).join(
        Project, Project.id == AIAnalysisRun.project_id
    ).filter(
        AIAnalysisRun.id == analysis_run_id,
        Project.owner_id == actor.id,
    ).first()
    if owned_run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")

    # Bind every evaluation to the same project as its parent run. This also
    # prevents inconsistent legacy rows from crossing a tenant boundary.
    return db.query(AIAnalysisEvaluation).join(
        AIAnalysisRun, AIAnalysisRun.id == AIAnalysisEvaluation.analysis_run_id
    ).filter(
        AIAnalysisEvaluation.analysis_run_id == analysis_run_id,
        AIAnalysisEvaluation.project_id == owned_run.project_id,
        AIAnalysisRun.project_id == owned_run.project_id,
    ).order_by(AIAnalysisEvaluation.id.asc()).all()
