from datetime import datetime, timezone
from uuid import UUID

import pytest

from app.core.evidence_coverage import assess_evidence_coverage
from app.schemas.validation_evidence import (
    ValidationEvidenceAssessment, ValidationEvidenceBundle, ValidationEvidenceItem,
)


def item(kind, relation="supports", refs=None, suffix="1"):
    return ValidationEvidenceItem(
        evidence_id=UUID(f"00000000-0000-4000-8000-{int(suffix):012d}"),
        evidence_type=kind, relationship=relation,
        statement=f"Human recorded evidence statement {suffix}",
        source_label=f"reviewer-{suffix}", observation_ids=refs or [],
        recorded_at=datetime.now(timezone.utc), human_attested=True,
    )


def bundle(items):
    return ValidationEvidenceBundle(
        strategy_id="auth_strategy", analysis_context_sha256="a" * 64,
        items=items, reviewed_at=datetime.now(timezone.utc),
    )


def assessment(b, contradictions=0):
    return ValidationEvidenceAssessment(
        strategy_id=b.strategy_id, evidence_status="mixed" if contradictions else "consistent",
        impact_status="documented_not_independently_verified" if any(x.evidence_type == "impact_context" for x in b.items) else "not_documented",
        readiness="more_evidence_required", supporting_evidence_count=sum(x.relationship == "supports" for x in b.items),
        contradicting_evidence_count=contradictions, context_evidence_count=sum(x.relationship == "context_only" for x in b.items),
        required_gaps=[], evidence_ids=[x.evidence_id for x in b.items],
        observation_ids=sorted({oid for x in b.items for oid in x.observation_ids}, key=str),
    )


def test_coverage_is_document_presence_not_confidence_or_severity():
    b = bundle([
        item("program_policy", refs=[UUID("00000000-0000-4000-8000-000000000001")]),
        item("expected_behavior", refs=[UUID("00000000-0000-4000-8000-000000000001")], suffix="2"),
        item("observed_behavior", refs=[UUID("00000000-0000-4000-8000-000000000001")], suffix="3"),
        item("authorized_test_account", suffix="4"),
        item("impact_context", refs=[UUID("00000000-0000-4000-8000-000000000001")], suffix="5"),
    ])
    result = assess_evidence_coverage(b, assessment(b))
    assert result.coverage_score == 100
    assert result.coverage_band == "complete"
    assert result.confidence_score is None
    assert result.vulnerability_severity is None
    assert result.impact_independently_verified is False


def test_partial_coverage_identifies_missing_elements_and_contradictions():
    b = bundle([
        item("observed_behavior", "contradicts",
             refs=[UUID("00000000-0000-4000-8000-000000000001")]),
    ])
    result = assess_evidence_coverage(b, assessment(b, contradictions=1))
    assert result.coverage_score == 40
    assert result.coverage_band == "partial"
    assert result.contradiction_count == 1
    assert "program_policy" in result.missing_elements
    assert "impact_context" in result.missing_elements


def test_rejects_mismatched_strategy_assessment():
    b = bundle([item("other")])
    wrong = assessment(b).model_copy(update={"strategy_id": "other_strategy"})
    with pytest.raises(ValueError, match="strategy IDs"):
        assess_evidence_coverage(b, wrong)
