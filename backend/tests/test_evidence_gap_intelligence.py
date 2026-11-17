from datetime import datetime, timezone
from uuid import UUID

import pytest

from app.core.evidence_gap_intelligence import build_evidence_gap_report
from app.schemas.validation_evidence import (
    ValidationEvidenceAssessment, ValidationEvidenceBundle, ValidationEvidenceItem,
)
from app.schemas.validation_strategy import ValidationStrategyItem


OBS = UUID("00000000-0000-4000-8000-000000000001")


def strategy():
    return ValidationStrategyItem(
        strategy_id="auth_strategy", category="object_authorization", priority="high",
        priority_basis="Observed route pairing only", hypothesis="Object authorization may be inconsistent",
        supporting_observation_ids=[str(OBS)], missing_evidence=[], validation_questions=["What is the expected rule?"],
        manual_review_actions=["Review the policy"], prerequisites=["Verify written authorization"],
    )


def item(kind, relation="supports", refs=None, suffix="1"):
    return ValidationEvidenceItem(
        evidence_id=UUID(f"00000000-0000-4000-8000-{int(suffix):012d}"),
        evidence_type=kind, relationship=relation,
        statement=f"Human recorded evidence statement {suffix}", source_label=f"reviewer-{suffix}",
        observation_ids=refs or [], recorded_at=datetime.now(timezone.utc), human_attested=True,
    )


def bundle(items):
    return ValidationEvidenceBundle(
        strategy_id="auth_strategy", analysis_context_sha256="a" * 64,
        items=items, reviewed_at=datetime.now(timezone.utc),
    )


def assessment(b):
    return ValidationEvidenceAssessment(
        strategy_id=b.strategy_id,
        evidence_status="mixed" if any(x.relationship == "contradicts" for x in b.items) else "consistent",
        impact_status="documented_not_independently_verified" if any(x.evidence_type == "impact_context" for x in b.items) else "not_documented",
        readiness="more_evidence_required", supporting_evidence_count=sum(x.relationship == "supports" for x in b.items),
        contradicting_evidence_count=sum(x.relationship == "contradicts" for x in b.items),
        context_evidence_count=sum(x.relationship == "context_only" for x in b.items),
        required_gaps=[], evidence_ids=[x.evidence_id for x in b.items],
        observation_ids=sorted({oid for x in b.items for oid in x.observation_ids}, key=str),
    )


def test_empty_evidence_bundle_is_not_allowed_by_contract_but_minimal_bundle_exposes_gaps():
    b = bundle([item("other")])
    report = build_evidence_gap_report(strategy(), b, assessment(b))
    categories = {gap.category for gap in report.gaps}
    assert {"program_policy", "expected_behavior", "observed_behavior", "impact_context"} <= categories
    assert report.hard_blocker_count == report.gap_count
    assert report.evidence_absence_interpretation == "missing_evidence_is_not_evidence_of_absence"


def test_missing_impact_is_not_reported_as_no_impact():
    b = bundle([item("observed_behavior", refs=[OBS])])
    report = build_evidence_gap_report(strategy(), b, assessment(b))
    gap = next(g for g in report.gaps if g.category == "impact_context")
    assert gap.observation_state == "not_documented"
    assert "not documented" in gap.reason
    assert "absent" not in gap.reason.casefold()


def test_contradiction_is_a_hard_blocker_and_keeps_evidence_references():
    b = bundle([item("observed_behavior", "contradicts", [OBS])])
    report = build_evidence_gap_report(strategy(), b, assessment(b))
    gap = next(g for g in report.gaps if g.category == "contradiction_resolution")
    assert gap.hard_blocker
    assert gap.observation_state == "contradictory"
    assert gap.related_evidence_ids == [str(b.items[0].evidence_id)]


def test_gap_ids_are_deterministic_and_only_reference_bundle_ids():
    b = bundle([item("program_policy", refs=[OBS]), item("other", suffix="2")])
    first = build_evidence_gap_report(strategy(), b, assessment(b))
    second = build_evidence_gap_report(strategy(), b, assessment(b))
    assert [g.gap_id for g in first.gaps] == [g.gap_id for g in second.gaps]
    valid_ids = {str(x.evidence_id) for x in b.items}
    valid_obs = {str(v) for x in b.items for v in x.observation_ids}
    assert all(set(g.related_evidence_ids) <= valid_ids for g in first.gaps)
    assert all(set(g.related_observation_ids) <= valid_obs for g in first.gaps)


def test_contradictory_policy_does_not_satisfy_policy_gap():
    b = bundle([item("program_policy", "contradicts", [OBS])])
    report = build_evidence_gap_report(strategy(), b, assessment(b))
    gap = next(g for g in report.gaps if g.category == "program_policy")
    assert gap.observation_state == "documented_but_unverified"


def test_rejects_detached_assessment_ids():
    b = bundle([item("other")])
    forged = assessment(b).model_copy(update={"evidence_ids": []})
    with pytest.raises(ValueError, match="evidence IDs"):
        build_evidence_gap_report(strategy(), b, forged)
