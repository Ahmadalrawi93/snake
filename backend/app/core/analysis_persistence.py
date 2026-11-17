"""Persistence boundary for completed AI triage; never invokes a provider."""
import hashlib
import json
from sqlalchemy.orm import Session

from app.db.models import AIAnalysisRun, Project, User
from app.core.analysis_redaction import redact_text
from app.schemas.analysis_context import AnalysisContext
from app.schemas.evidence_correlation import CorrelationReport
from app.schemas.observation_triage import ObservationTriage


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
) -> AIAnalysisRun:
    """Store only validated triage and digests, not raw prompts, evidence, or credentials."""
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise ValueError("project is not owned by actor")
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
    record = AIAnalysisRun(
        project_id=project.id,
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
