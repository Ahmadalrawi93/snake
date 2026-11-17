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
    record = db.query(AIAnalysisEvaluation).join(
        Project, Project.id == AIAnalysisEvaluation.project_id
    ).filter(
        AIAnalysisEvaluation.analysis_run_id == analysis_run_id,
        Project.owner_id == actor.id,
    ).order_by(AIAnalysisEvaluation.id.asc()).all()
    if not record:
        # Avoid leaking whether a run exists outside this user's project.
        exists = db.query(AIAnalysisEvaluation.id).filter_by(analysis_run_id=analysis_run_id).first()
        if exists is None:
            # An empty list is valid only if the analysis run itself is owned.
            from app.db.models import AIAnalysisRun
            owned = db.query(AIAnalysisRun.id).join(Project).filter(
                AIAnalysisRun.id == analysis_run_id, Project.owner_id == actor.id
            ).first()
            if owned:
                return []
        raise HTTPException(status_code=404, detail="Analysis run not found")
    return record
