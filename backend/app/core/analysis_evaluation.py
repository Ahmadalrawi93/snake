"""Human-only evaluation and conservative aggregate metrics."""
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import AIAnalysisEvaluation, AIAnalysisRun, Project, User
from app.schemas.analysis_evaluations import AnalysisEvaluationCreate


def record_human_evaluation(
    db: Session, *, analysis_run_id: int, actor: User, payload: AnalysisEvaluationCreate
) -> AIAnalysisEvaluation:
    run = db.query(AIAnalysisRun).join(
        Project, Project.id == AIAnalysisRun.project_id
    ).filter(
        AIAnalysisRun.id == analysis_run_id,
        Project.owner_id == actor.id,
    ).first()
    if run is None:
        raise LookupError("analysis run not found")
    prior = db.query(AIAnalysisEvaluation.id).filter_by(
        analysis_run_id=run.id, evaluator_id=actor.id
    ).first()
    if prior is not None:
        raise ValueError("reviewer has already evaluated this analysis run")
    record = AIAnalysisEvaluation(
        analysis_run_id=run.id,
        project_id=run.project_id,
        evaluator_id=actor.id,
        outcome=payload.outcome,
        evidence_sha256=payload.evidence_sha256,
        validation_method=payload.validation_method,
        notes=payload.notes,
    )
    db.add(record)
    db.flush()
    return record


def get_project_evaluation_metrics(db: Session, *, project_id: int, actor: User) -> dict:
    owned = db.query(Project.id).filter_by(id=project_id, owner_id=actor.id).first()
    if owned is None:
        raise LookupError("project not found")
    counts = {
        row[0]: row[1]
        for row in db.query(AIAnalysisEvaluation.outcome, func.count(AIAnalysisEvaluation.id))
        .filter(AIAnalysisEvaluation.project_id == project_id)
        .group_by(AIAnalysisEvaluation.outcome)
        .all()
    }
    confirmed = counts.get("confirmed", 0)
    false_positive = counts.get("false_positive", 0)
    inconclusive = counts.get("inconclusive", 0)
    duplicate = counts.get("duplicate", 0)
    reviewed = confirmed + false_positive + inconclusive + duplicate
    resolved = confirmed + false_positive
    return {
        "reviewed": reviewed,
        "confirmed": confirmed,
        "false_positive": false_positive,
        "inconclusive": inconclusive,
        "duplicate": duplicate,
        "resolved_precision": confirmed / resolved if resolved else None,
        "resolution_coverage": resolved / reviewed if reviewed else 0.0,
    }
