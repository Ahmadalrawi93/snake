from datetime import datetime, timezone
from uuid import UUID

import pytest

from app.core.evidence_gap_intelligence import build_evidence_gap_report
from app.core.evidence_acquisition_planner import build_evidence_acquisition_plan
from app.schemas.validation_evidence import ValidationEvidenceAssessment, ValidationEvidenceBundle, ValidationEvidenceItem
from app.schemas.validation_strategy import ValidationStrategyItem


OBS = UUID("00000000-0000-4000-8000-000000000001")


def fixtures():
    strategy = ValidationStrategyItem(
        strategy_id="auth_strategy", category="object_authorization", priority="high",
        priority_basis="Observed route pairing", hypothesis="Object authorization may be inconsistent",
        supporting_observation_ids=[str(OBS)], missing_evidence=[], validation_questions=["What is expected?"],
        manual_review_actions=["Review existing authorized records"], prerequisites=["Written permission"],
    )
    now = datetime.now(timezone.utc)
    bundle = ValidationEvidenceBundle(
        strategy_id=strategy.strategy_id, analysis_context_sha256="a" * 64,
        items=[ValidationEvidenceItem(
            evidence_id=UUID("00000000-0000-4000-8000-000000000002"),
            evidence_type="other", relationship="context_only",
            statement="Contextual evidence record retained for review", source_label="reviewer",
            observation_ids=[OBS], recorded_at=now, human_attested=True,
        )], reviewed_at=now,
    )
    assessment = ValidationEvidenceAssessment(
        strategy_id=strategy.strategy_id, evidence_status="insufficient",
        impact_status="not_documented", readiness="more_evidence_required",
        supporting_evidence_count=0, contradicting_evidence_count=0, context_evidence_count=1,
        required_gaps=[], evidence_ids=[bundle.items[0].evidence_id], observation_ids=[OBS],
    )
    report = build_evidence_gap_report(strategy, bundle, assessment)
    return strategy, bundle, report


def test_plan_is_deterministic_prioritized_and_manual_only():
    strategy, bundle, report = fixtures()
    first = build_evidence_acquisition_plan(strategy, bundle, report)
    second = build_evidence_acquisition_plan(strategy, bundle, report)
    assert first == second
    assert first.execution_enabled is False
    assert first.disposition == "human_coordinated_evidence_collection_only"
    assert first.steps[0].category == "program_policy"
    assert all(step.manual_only for step in first.steps)
    assert all(step.step_id not in step.depends_on_step_ids for step in first.steps)


def test_plan_never_requests_production_probing_or_real_user_data():
    strategy, bundle, report = fixtures()
    plan = build_evidence_acquisition_plan(strategy, bundle, report)
    serialized = str(plan.model_dump()).casefold()
    assert "real-user accounts" in serialized
    assert "production probing" in serialized
    assert "payloads" in serialized


def test_plan_rejects_gap_references_not_in_bundle():
    strategy, bundle, report = fixtures()
    forged_gap = report.gaps[0].model_copy(update={"related_evidence_ids": ["f" * 36]})
    forged_report = report.model_copy(update={"gaps": [forged_gap, *report.gaps[1:]]})
    with pytest.raises(ValueError, match="outside the supplied bundle"):
        build_evidence_acquisition_plan(strategy, bundle, forged_report)


def test_plan_rejects_strategy_or_report_count_mismatch():
    strategy, bundle, report = fixtures()
    with pytest.raises(ValueError, match="must match"):
        build_evidence_acquisition_plan(strategy, bundle, report.model_copy(update={"strategy_id": "other"}))
    with pytest.raises(ValueError, match="count"):
        build_evidence_acquisition_plan(strategy, bundle, report.model_copy(update={"gap_count": 0}))
