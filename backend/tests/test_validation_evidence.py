from datetime import datetime, timezone, timedelta
from uuid import UUID, uuid4

import pytest

from app.core.analysis_context import build_analysis_context
from app.core.validation_strategy import build_validation_strategy
from app.core.business_logic_intelligence import build_business_logic_profile
from app.core.cross_surface_reasoning import build_cross_surface_profile
from app.core.validation_evidence import assess_validation_evidence
from app.schemas.observation_triage import ObservationTriage
from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceItem
from app.schemas.worker_results import WorkerObservation


def fixture_inputs():
    now = datetime.now(timezone.utc)
    observation_id = uuid4()
    observation = WorkerObservation(
        observation_id=observation_id, kind="url",
        value="https://app.example.test/api/orders/123",
        evidence="observed route", source="passive", observed_at=now,
    )
    context = build_analysis_context([observation])
    triage = ObservationTriage(
        category="business_logic", hypothesis="Review order authorization behavior.",
        supporting_observation_ids=[observation_id],
        missing_evidence=["Expected and observed behavior"],
        validation_questions=["What should an authorized test identity be allowed to do?"],
        confidence="medium",
    )
    business = build_business_logic_profile(context)
    strategy = build_validation_strategy(
        context, triage, business, build_cross_surface_profile(context, business),
    ).items[0]
    return context, strategy, observation_id, now


def item(kind, relation, observation_id, now, statement):
    return ValidationEvidenceItem(
        evidence_id=uuid4(), evidence_type=kind, relationship=relation,
        statement=statement, source_label="reviewer-provided record",
        observation_ids=[observation_id], recorded_at=now, human_attested=True,
    )


def bundle(strategy, observation_id, now, kinds):
    entries = [item(k, r, observation_id, now, s) for k, r, s in kinds]
    return ValidationEvidenceBundle(
        strategy_id=strategy.strategy_id, analysis_context_sha256="a"*64,
        items=entries, reviewed_at=now + timedelta(seconds=1),
    )


def test_complete_evidence_is_ready_for_human_review_not_confirmation():
    context, strategy, oid, now = fixture_inputs()
    evidence = bundle(strategy, oid, now, [
        ("program_policy", "context_only", "Written program policy permits this review."),
        ("expected_behavior", "context_only", "The documented expected behavior is access denied."),
        ("observed_behavior", "supports", "An authorized test identity observed the documented behavior."),
        ("impact_context", "context_only", "The affected resource is a program-provided test order."),
    ])
    result = assess_validation_evidence(context, strategy, evidence, expected_context_sha256="a"*64)
    assert result.readiness == "human_review_ready"
    assert result.evidence_status == "consistent"
    assert result.impact_status == "documented_not_independently_verified"
    assert result.disposition == "requires_independent_human_validation"
    assert result.execution_enabled is False


def test_missing_impact_and_policy_keeps_evidence_incomplete():
    context, strategy, oid, now = fixture_inputs()
    evidence = bundle(strategy, oid, now, [
        ("expected_behavior", "context_only", "Documented behavior is access denied."),
        ("observed_behavior", "supports", "Observed behavior in a designated test account."),
    ])
    result = assess_validation_evidence(context, strategy, evidence, expected_context_sha256="a"*64)
    assert result.readiness == "more_evidence_required"
    assert "impact_evidence_and_affected_asset_context" in result.required_gaps
    assert "program_policy_or_written_permission" in result.required_gaps


def test_contradictory_evidence_is_marked_mixed():
    context, strategy, oid, now = fixture_inputs()
    evidence = bundle(strategy, oid, now, [
        ("program_policy", "context_only", "Written policy authorizes a bounded test."),
        ("expected_behavior", "context_only", "Expected access is denied."),
        ("observed_behavior", "supports", "One test observation supports the hypothesis."),
        ("observed_behavior", "contradicts", "A separate authorized observation contradicts it."),
        ("impact_context", "context_only", "Only test data is involved."),
    ])
    result = assess_validation_evidence(context, strategy, evidence, expected_context_sha256="a"*64)
    assert result.evidence_status == "mixed"
    assert result.readiness == "human_review_ready"


def test_rejects_foreign_observation_reference():
    context, strategy, oid, now = fixture_inputs()
    foreign = item("observed_behavior", "supports", uuid4(), now, "An observation outside this context.")
    evidence = ValidationEvidenceBundle(
        strategy_id=strategy.strategy_id, analysis_context_sha256="a"*64,
        items=[foreign], reviewed_at=now + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="outside analysis context"):
        assess_validation_evidence(context, strategy, evidence, expected_context_sha256="a"*64)


def test_rejects_wrong_strategy_or_context_digest():
    context, strategy, oid, now = fixture_inputs()
    evidence = bundle(strategy, oid, now, [
        ("observed_behavior", "supports", "Observed behavior under authorized test context."),
    ])
    with pytest.raises(ValueError, match="context digest"):
        assess_validation_evidence(context, strategy, evidence, expected_context_sha256="b"*64)
    other = strategy.model_copy(update={"strategy_id": "different_strategy"})
    with pytest.raises(ValueError, match="does not match"):
        assess_validation_evidence(context, other, evidence, expected_context_sha256="a"*64)
