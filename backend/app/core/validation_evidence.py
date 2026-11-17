"""Deterministic assessment of human-recorded evidence; no exploit confirmation."""
from uuid import UUID

from app.schemas.analysis_context import AnalysisContext
from app.schemas.validation_strategy import ValidationStrategyItem
from app.schemas.validation_evidence import (
    ValidationEvidenceAssessment, ValidationEvidenceBundle,
)


def _context_ids(context: AnalysisContext) -> set[UUID]:
    raw = [
        value
        for group in context.groups for observation in group.observations
        for value in observation.observation_ids
    ] + [
        value for observation in context.ungrouped
        for value in observation.observation_ids
    ]
    return {UUID(value) for value in raw}


def assess_validation_evidence(
    context: AnalysisContext,
    strategy: ValidationStrategyItem,
    bundle: ValidationEvidenceBundle,
    *,
    expected_context_sha256: str,
) -> ValidationEvidenceAssessment:
    """Check evidence completeness and provenance; never decides vulnerability status."""
    if bundle.strategy_id != strategy.strategy_id:
        raise ValueError("evidence bundle does not match validation strategy")
    if bundle.analysis_context_sha256 != expected_context_sha256:
        raise ValueError("evidence bundle context digest mismatch")
    if not expected_context_sha256 or len(expected_context_sha256) != 64:
        raise ValueError("invalid expected context digest")

    available = _context_ids(context)
    strategy_ids = {UUID(value) for value in strategy.supporting_observation_ids}
    if not strategy_ids.issubset(available):
        raise ValueError("strategy references observations outside analysis context")

    evidence_observation_ids: set[UUID] = set()
    for item in bundle.items:
        referenced = set(item.observation_ids)
        if not referenced.issubset(available):
            raise ValueError("evidence references observations outside analysis context")
        if item.evidence_type in {"expected_behavior", "observed_behavior", "impact_context"}:
            if not referenced:
                raise ValueError("required evidence type has no source observations")
        evidence_observation_ids.update(referenced)

    supporting = [item for item in bundle.items if item.relationship == "supports"]
    contradicting = [item for item in bundle.items if item.relationship == "contradicts"]
    contextual = [item for item in bundle.items if item.relationship == "context_only"]

    types = {item.evidence_type for item in bundle.items}
    gaps = []
    if "program_policy" not in types:
        gaps.append("program_policy_or_written_permission")
    if "expected_behavior" not in types:
        gaps.append("documented_expected_behavior")
    if "observed_behavior" not in types:
        gaps.append("observed_behavior_from_an_authorized_test_context")
    if "impact_context" not in types:
        gaps.append("impact_evidence_and_affected_asset_context")
    if not any(item.evidence_type == "observed_behavior" and item.relationship == "supports" for item in bundle.items):
        gaps.append("supporting_observed_behavior")
    if not strategy_ids.intersection(evidence_observation_ids):
        gaps.append("evidence_linked_to_strategy_observations")

    if not supporting:
        evidence_status = "insufficient"
    elif contradicting:
        evidence_status = "mixed"
    else:
        evidence_status = "consistent"

    impact_documented = "impact_context" in types
    readiness = "human_review_ready" if not gaps else "more_evidence_required"

    return ValidationEvidenceAssessment(
        strategy_id=strategy.strategy_id,
        evidence_status=evidence_status,
        impact_status=(
            "documented_not_independently_verified"
            if impact_documented else "not_documented"
        ),
        readiness=readiness,
        supporting_evidence_count=len(supporting),
        contradicting_evidence_count=len(contradicting),
        context_evidence_count=len(contextual),
        required_gaps=gaps,
        evidence_ids=[item.evidence_id for item in bundle.items],
        observation_ids=sorted(evidence_observation_ids, key=str),
    )
