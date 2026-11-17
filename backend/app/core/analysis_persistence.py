"""Persistence boundary for completed AI triage; never invokes a provider."""
import hashlib
import json
from sqlalchemy.orm import Session

from app.db.models import AIAnalysisRun, Project, Target, User
from app.core.analysis_redaction import redact_text
from app.schemas.analysis_context import AnalysisContext
from app.schemas.evidence_correlation import CorrelationReport
from app.schemas.observation_triage import ObservationTriage
from app.schemas.validation_strategy import ValidationStrategyPlan
from app.core.deepseek_analysis import AnalysisExecutionResult


def _canonical_digest(value) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def persist_analysis_run(
    db: Session,
    *,
    project_id: int,
    actor: User,
    context: AnalysisContext,
    correlations: CorrelationReport,
    triage: ObservationTriage,
    model: str,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    total_tokens: int | None = None,
    cost_usd: str | None = None,
    provider_request_id: str | None = None,
    target_id: int | None = None,
    validation_strategy: ValidationStrategyPlan | None = None,
) -> AIAnalysisRun:
    """Store only validated triage and digests, not raw prompts, evidence, or credentials."""
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise ValueError("project is not owned by actor")
    if target_id is not None and db.query(Target.id).filter_by(id=target_id, project_id=project_id).first() is None:
        raise ValueError("target does not belong to project")
    if not model or len(model) > 100 or any(ord(c) < 33 for c in model):
        raise ValueError("invalid model")
    for value in (prompt_tokens, completion_tokens, total_tokens):
        if value is not None and (isinstance(value, bool) or value < 0):
            raise ValueError("token usage must be non-negative")
    if cost_usd is not None and (len(cost_usd) > 32 or not cost_usd.replace(".", "", 1).isdigit()):
        raise ValueError("cost must be a non-negative decimal string")
    if provider_request_id is not None and len(provider_request_id) > 160:
        raise ValueError("provider request ID too long")

    context_data = context.model_dump(mode="json")
    correlations_data = correlations.model_dump(mode="json")
    result_data = triage.model_dump(mode="json")
    result_data["hypothesis"] = redact_text(result_data["hypothesis"])
    result_data["missing_evidence"] = [redact_text(value) for value in result_data["missing_evidence"]]
    result_data["validation_questions"] = [redact_text(value) for value in result_data["validation_questions"]]
    if validation_strategy is not None:
        available_ids = {
            value
            for group in context.groups for item in group.observations
            for value in item.observation_ids
        } | {
            value for item in context.ungrouped for value in item.observation_ids
        }
        strategy_data = validation_strategy.model_dump(mode="json")
        for strategy_item in strategy_data["items"]:
            if not set(strategy_item["supporting_observation_ids"]).issubset(available_ids):
                raise ValueError("validation strategy references observations outside analysis context")
            for field in ("priority_basis", "hypothesis"):
                strategy_item[field] = redact_text(strategy_item[field])
            for field in ("missing_evidence", "validation_questions", "manual_review_actions", "prerequisites"):
                strategy_item[field] = [redact_text(value) for value in strategy_item[field]]
        result_data["validation_strategy"] = strategy_data
    record = AIAnalysisRun(
        project_id=project.id,
        target_id=target_id,
        created_by=actor.id,
        context_sha256=_canonical_digest(context_data),
        correlations_sha256=_canonical_digest(correlations_data),
        provider="deepseek",
        model=model,
        status="completed",
        disposition="requires_independent_validation",
        result_json=json.dumps(result_data, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        cost_usd=cost_usd,
        provider_request_id=provider_request_id,
        execution_enabled=False,
    )
    db.add(record)
    db.flush()
    return record



def persist_analysis_execution(
    db: Session,
    *,
    project_id: int,
    actor: User,
    context: AnalysisContext,
    correlations: CorrelationReport,
    execution: AnalysisExecutionResult,
    cost_usd: str | None = None,
    target_id: int | None = None,
) -> AIAnalysisRun:
    """Persist an explicit provider execution using its validated output and usage metadata."""
    if execution.provider != "deepseek":
        raise ValueError("unsupported analysis provider")
    return persist_analysis_run(
        db,
        project_id=project_id,
        actor=actor,
        context=context,
        correlations=correlations,
        triage=execution.triage,
        validation_strategy=execution.validation_strategy,
        model=execution.model,
        prompt_tokens=execution.prompt_tokens,
        completion_tokens=execution.completion_tokens,
        total_tokens=execution.total_tokens,
        cost_usd=cost_usd,
        provider_request_id=execution.provider_request_id,
        target_id=target_id,
    )
