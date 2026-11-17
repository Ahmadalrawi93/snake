"""Owner-checked persistent hypothesis history, scoped to one project and target."""
import hashlib
import json
import re
from sqlalchemy.orm import Session
from app.db.models import AIAnalysisRun, InvestigationMemoryRecord, Project, User
from app.schemas.validation_strategy import ValidationStrategyItem
from app.schemas.investigation_memory import InvestigationMemoryReport, PriorInvestigationMatch

def _normalize(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.casefold()).split())

def hypothesis_fingerprint(strategy: ValidationStrategyItem) -> str:
    raw = strategy.category + "\\0" + _normalize(strategy.hypothesis)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def record_and_compare_investigation_memory(
    db: Session, *, run: AIAnalysisRun, strategy: ValidationStrategyItem, actor: User,
) -> InvestigationMemoryReport:
    owned = db.query(AIAnalysisRun).join(Project, Project.id == AIAnalysisRun.project_id).filter(
        AIAnalysisRun.id == run.id, Project.owner_id == actor.id,
        AIAnalysisRun.project_id == run.project_id, AIAnalysisRun.target_id == run.target_id,
    ).first()
    if owned is None or run.target_id is None:
        raise LookupError("owned target analysis run not found")
    fp = hypothesis_fingerprint(strategy)
    current_obs = sorted(set(strategy.supporting_observation_ids))
    prior_rows = db.query(InvestigationMemoryRecord).filter(
        InvestigationMemoryRecord.project_id == run.project_id,
        InvestigationMemoryRecord.target_id == run.target_id,
        InvestigationMemoryRecord.hypothesis_fingerprint == fp,
        InvestigationMemoryRecord.analysis_run_id != run.id,
    ).order_by(InvestigationMemoryRecord.created_at.desc(), InvestigationMemoryRecord.id.desc()).limit(50).all()
    matches = []
    for row in prior_rows:
        old_obs = set(json.loads(row.observation_ids_json))
        shared = old_obs.intersection(current_obs)
        new = set(current_obs).difference(old_obs)
        matches.append(PriorInvestigationMatch(
            analysis_run_id=row.analysis_run_id, strategy_id=row.strategy_id,
            shared_observation_count=len(shared), new_observation_count=len(new),
            disposition="new_observations_available" if new else "previously_seen_no_new_observations",
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
            execution_enabled=False,
        ))
        db.flush()
    elif existing.hypothesis_fingerprint != fp or json.loads(existing.observation_ids_json) != current_obs:
        raise ValueError("investigation memory entry already exists with different content")
    return InvestigationMemoryReport(
        current_strategy_id=strategy.strategy_id, hypothesis_fingerprint=fp,
        prior_matches=matches, memory_scope="same_project_and_same_target_only",
    )
