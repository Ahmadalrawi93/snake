"""Persist authenticated, append-only human decisions for finding candidates."""
from sqlalchemy.orm import Session

from app.core.analysis_redaction import redact_text
from app.db.models import AIAnalysisRun, HumanFindingDecision, Project, User
from app.schemas.finding_decisions import HumanFindingDecisionCreate


def record_human_finding_decision(
    db: Session, *, analysis_run_id: int, actor: User,
    payload: HumanFindingDecisionCreate,
) -> HumanFindingDecision:
    run = db.query(AIAnalysisRun).join(
        Project, Project.id == AIAnalysisRun.project_id
    ).filter(
        AIAnalysisRun.id == analysis_run_id,
        Project.owner_id == actor.id,
    ).first()
    if run is None:
        raise LookupError("analysis run not found")

    prior = db.query(HumanFindingDecision.id).filter_by(
        analysis_run_id=run.id,
        candidate_fingerprint=payload.candidate_fingerprint,
        evaluator_id=actor.id,
    ).first()
    if prior is not None:
        raise ValueError("reviewer has already decided on this candidate")

    record = HumanFindingDecision(
        analysis_run_id=run.id,
        project_id=run.project_id,
        evaluator_id=actor.id,
        candidate_fingerprint=payload.candidate_fingerprint,
        outcome=payload.outcome,
        evidence_sha256=payload.evidence_sha256,
        validation_method=payload.validation_method,
        notes=redact_text(payload.notes),
        reviewer_attested=True,
    )
    db.add(record)
    db.flush()
    return record


def list_human_finding_decisions(
    db: Session, *, analysis_run_id: int, candidate_fingerprint: str, actor: User
) -> list[HumanFindingDecision]:
    owned = db.query(AIAnalysisRun.id).join(
        Project, Project.id == AIAnalysisRun.project_id
    ).filter(
        AIAnalysisRun.id == analysis_run_id,
        Project.owner_id == actor.id,
    ).first()
    if owned is None:
        raise LookupError("analysis run not found")
    return db.query(HumanFindingDecision).filter_by(
        analysis_run_id=analysis_run_id,
        candidate_fingerprint=candidate_fingerprint,
    ).order_by(HumanFindingDecision.id.asc()).all()
