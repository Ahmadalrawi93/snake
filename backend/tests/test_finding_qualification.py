from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.finding_qualification import qualify_finding_candidate
from app.schemas.validation_strategy import ValidationStrategyItem
from app.schemas.validation_evidence import (
    ValidationEvidenceAssessment, ValidationEvidenceBundle, ValidationEvidenceItem,
)


def fixtures():
    observation_id = uuid4()
    strategy = ValidationStrategyItem(
        strategy_id="object_access_review", category="object_authorization",
        priority="high", priority_basis="Observed resource routes",
        hypothesis="A user may access another user's private invoice",
        supporting_observation_ids=[str(observation_id)],
        missing_evidence=[], validation_questions=["Is ownership enforced?"],
        manual_review_actions=["Review authorized test-account behavior"],
        prerequisites=["Written program permission"],
    )
    now = datetime.now(timezone.utc)
    items = [
        ("program_policy", "supports", []),
        ("expected_behavior", "supports", [observation_id]),
        ("observed_behavior", "supports", [observation_id]),
        ("impact_context", "supports", [observation_id]),
    ]
    bundle = ValidationEvidenceBundle(
        strategy_id=strategy.strategy_id, analysis_context_sha256="a" * 64,
        items=[
            ValidationEvidenceItem(
                evidence_id=uuid4(), evidence_type=kind, relationship=relationship,
                statement="Documented evidence statement", source_label="review_record",
                observation_ids=ids, recorded_at=now, human_attested=True,
            ) for kind, relationship, ids in items
        ], reviewed_at=now,
    )
    assessment = ValidationEvidenceAssessment(
        strategy_id=strategy.strategy_id, evidence_status="consistent",
        impact_status="documented_not_independently_verified",
        readiness="human_review_ready", supporting_evidence_count=4,
        contradicting_evidence_count=0, context_evidence_count=0,
        required_gaps=[], evidence_ids=[item.evidence_id for item in bundle.items],
        observation_ids=[observation_id],
    )
    return strategy, bundle, assessment


def test_complete_evidence_only_yields_unconfirmed_human_review_candidate():
    strategy, bundle, assessment = fixtures()
    result = qualify_finding_candidate(strategy, bundle, assessment)
    assert result.qualification == "human_review_candidate"
    assert result.finding_status == "unconfirmed"
    assert result.execution_enabled is False
    assert result.disposition == "unconfirmed_candidate_requires_human_decision"


@pytest.mark.parametrize("changes", [
    {"evidence_status": "mixed", "contradicting_evidence_count": 1},
    {"readiness": "more_evidence_required", "required_gaps": ["documented_expected_behavior"]},
    {"impact_status": "not_documented"},
])
def test_incomplete_or_conflicting_evidence_never_becomes_candidate(changes):
    strategy, bundle, assessment = fixtures()
    if changes.get("evidence_status") == "mixed":
        original = bundle.items[-1]
        bundle.items[-1] = original.model_copy(update={"relationship": "contradicts"})
        from app.core.validation_evidence import assess_validation_evidence
        from app.schemas.analysis_context import AnalysisContext
        # Build a minimal context carrying every referenced observation ID.
        from app.schemas.analysis_context import ContextObservation
        context = AnalysisContext(
            groups=[], ungrouped=[
                ContextObservation(
                    kind="url", value="/api/users/1", evidence="observed",
                    source="test", observation_ids=[str(value)]
                ) for value in {oid for item in bundle.items for oid in item.observation_ids}
            ], trust_notice="Untrusted test evidence"
        )
        assessment = assess_validation_evidence(
            context, strategy, bundle, expected_context_sha256=bundle.analysis_context_sha256
        )
    else:
        data = assessment.model_dump()
        data.update(changes)
        assessment = ValidationEvidenceAssessment.model_validate(data)
    result = qualify_finding_candidate(strategy, bundle, assessment)
    assert result.qualification == "insufficient_evidence"
    assert result.finding_status == "unconfirmed"
    assert result.blockers


def test_duplicate_fingerprint_is_not_promoted_again():
    strategy, bundle, assessment = fixtures()
    first = qualify_finding_candidate(strategy, bundle, assessment)
    second = qualify_finding_candidate(
        strategy, bundle, assessment,
        prior_candidate_fingerprints=[first.candidate_fingerprint],
    )
    assert second.qualification == "insufficient_evidence"
    assert second.duplicate_of_fingerprint == first.candidate_fingerprint
    assert "candidate_matches_a_prior_category_and_hypothesis_fingerprint" in second.blockers


def test_strategy_mismatch_rejected():
    strategy, bundle, assessment = fixtures()
    bundle.strategy_id = "another_strategy"
    with pytest.raises(ValueError):
        qualify_finding_candidate(strategy, bundle, assessment)


def test_invalid_prior_fingerprint_rejected():
    strategy, bundle, assessment = fixtures()
    with pytest.raises(ValueError):
        qualify_finding_candidate(strategy, bundle, assessment, prior_candidate_fingerprints=["bad"])



def test_detached_assessment_evidence_ids_are_rejected():
    strategy, bundle, assessment = fixtures()
    data = assessment.model_dump()
    data["evidence_ids"] = [uuid4()]
    detached = ValidationEvidenceAssessment.model_validate(data)
    with pytest.raises(ValueError, match="evidence IDs"):
        qualify_finding_candidate(strategy, bundle, detached)


def test_forged_assessment_counts_are_rejected():
    strategy, bundle, assessment = fixtures()
    data = assessment.model_dump()
    data["supporting_evidence_count"] += 1
    detached = ValidationEvidenceAssessment.model_validate(data)
    with pytest.raises(ValueError, match="supporting_evidence_count"):
        qualify_finding_candidate(strategy, bundle, detached)
