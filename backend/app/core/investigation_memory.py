"""Owner-checked persistent hypothesis history with verified human-decision linkage."""
import hashlib
import json
import re
import unicodedata
from sqlalchemy.orm import Session
from app.db.models import AIAnalysisRun, HumanFindingDecision, InvestigationMemoryRecord, Project, User
from app.schemas.validation_strategy import ValidationStrategyItem
from app.schemas.investigation_memory import InvestigationMemoryReport, PriorInvestigationMatch

def _normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return " ".join("".join(char if char.isalnum() else " " for char in normalized).split())

def hypothesis_fingerprint(strategy: ValidationStrategyItem) -> str:
    raw = strategy.category + "\0" + _normalize(strategy.hypothesis)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def record_and_compare_investigation_memory(
    db: Session, *, run: AIAnalysisRun, strategy: ValidationStrategyItem, actor: User,
    candidate_fingerprint: str | None = None,
) -> InvestigationMemoryReport:
    owned = db.query(AIAnalysisRun).join(Project, Project.id == AIAnalysisRun.project_id).filter(
        AIAnalysisRun.id == run.id, Project.owner_id == actor.id,
        AIAnalysisRun.project_id == run.project_id, AIAnalysisRun.target_id == run.target_id,
    ).first()
    if owned is None or run.target_id is None:
        raise LookupError("owned target analysis run not found")
    fp = hypothesis_fingerprint(strategy)
    current_obs_set = set(strategy.supporting_observation_ids)
    current_obs = sorted(current_obs_set)
    prior_rows = db.query(InvestigationMemoryRecord).filter(
        InvestigationMemoryRecord.project_id == run.project_id,
        InvestigationMemoryRecord.target_id == run.target_id,
        InvestigationMemoryRecord.hypothesis_fingerprint == fp,
        InvestigationMemoryRecord.analysis_run_id != run.id,
    ).order_by(InvestigationMemoryRecord.created_at.desc(), InvestigationMemoryRecord.id.desc()).limit(50).all()
    matches = []
    for row in prior_rows:
        old_obs = set(json.loads(row.observation_ids_json))
        shared = old_obs.intersection(current_obs_set)
        new = current_obs_set.difference(old_obs)
        outcomes = []
        if row.candidate_fingerprint:
            outcomes = [item[0] for item in db.query(HumanFindingDecision.outcome).filter(
                HumanFindingDecision.project_id == run.project_id,
                HumanFindingDecision.analysis_run_id == row.analysis_run_id,
                HumanFindingDecision.candidate_fingerprint == row.candidate_fingerprint,
                HumanFindingDecision.reviewer_attested.is_(True),
            ).order_by(HumanFindingDecision.id.asc()).limit(20).all()]
        matches.append(PriorInvestigationMatch(
            analysis_run_id=row.analysis_run_id, strategy_id=row.strategy_id,
            shared_observation_count=len(shared), new_observation_count=len(new),
            disposition="new_observations_available" if new else "previously_seen_no_new_observations",
            human_outcomes=outcomes, review_state="human_reviewed" if outcomes else "not_reviewed",
        ))
    existing = db.query(InvestigationMemoryRecord).filter_by(
        analysis_run_id=run.id, strategy_id=strategy.strategy_id
    ).first()
    if existing is None:
        db.add(InvestigationMemoryRecord(
            project_id=run.project_id, target_id=run.target_id, analysis_run_id=run.id,
            strategy_id=strategy.strategy_id, hypothesis_fingerprint=fp,
            category=strategy.category, hypothesis_text=strategy.hypothesis,
            observation_ids_json=json.dumps(current_obs, separators=(",", ":")),
            candidate_fingerprint=candidate_fingerprint, execution_enabled=False,
        ))
        db.flush()
    elif existing.hypothesis_fingerprint != fp or json.loads(existing.observation_ids_json) != current_obs or (
        candidate_fingerprint is not None and existing.candidate_fingerprint not in {None, candidate_fingerprint}
    ):
        raise ValueError("investigation memory entry already exists with different content")
    elif candidate_fingerprint is not None and existing.candidate_fingerprint is None:
        existing.candidate_fingerprint = candidate_fingerprint
        db.flush()
    return InvestigationMemoryReport(
        current_strategy_id=strategy.strategy_id, hypothesis_fingerprint=fp,
        prior_matches=matches, memory_scope="same_project_and_same_target_only",
    )
