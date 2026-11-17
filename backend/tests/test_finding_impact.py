from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.finding_impact import assess_finding_impact
from app.schemas.finding_impact import FindingImpactClaim
from app.schemas.finding_qualification import FindingQualification
from app.schemas.validation_evidence import (
    ValidationEvidenceAssessment, ValidationEvidenceBundle, ValidationEvidenceItem,
)


def make_inputs():
    observation_id = uuid4()
    impact = ValidationEvidenceItem(
        evidence_id=uuid4(), evidence_type="impact_context", relationship="supports",
        statement="Synthetic order record was readable by the second designated test account.",
        source_label="authorized test", observation_ids=[observation_id],
        recorded_at=datetime.now(timezone.utc), human_attested=True,
    )
    bundle = ValidationEvidenceBundle(
        strategy_id="idor_test", analysis_context_sha256="a" * 64,
        items=[impact], reviewed_at=datetime.now(timezone.utc),
    )
    qualification = FindingQualification(
        candidate_fingerprint="b" * 64, category="idor",
        title="Potential cross-account object access", qualification="human_review_candidate",
        evidence_quality="documented_consistent",
        impact_quality="documented_not_independently_verified", blockers=[],
        evidence_ids=[str(impact.evidence_id)], observation_ids=[str(observation_id)],
    )
    assessment = ValidationEvidenceAssessment(
        strategy_id="idor_test", evidence_status="consistent",
        impact_status="documented_not_independently_verified", readiness="human_review_ready",
        supporting_evidence_count=1, contradicting_evidence_count=0, context_evidence_count=0,
        required_gaps=[], evidence_ids=[impact.evidence_id], observation_ids=[observation_id],
    )
    return qualification, bundle, assessment, impact, observation_id


def claim(impact, observation_id, **overrides):
    values = dict(
        evidence_id=impact.evidence_id, observation_ids=[observation_id],
        dimension="confidentiality", level="high", verification="observed",
        scope="multiple_records", data_sensitivity="sensitive_data",
        statement="A second authorized test identity read protected synthetic records.",
        human_attested=True,
    )
    values.update(overrides)
    return FindingImpactClaim(**values)


def test_observed_and_linked_impact_produces_only_a_severity_suggestion():
    q, b, a, item, obs = make_inputs()
    result = assess_finding_impact(q, b, a, [claim(item, obs)])
    assert result.assessment_status == "documented_not_independently_verified"
    assert result.demonstrated_dimensions == ["confidentiality"]
    assert result.severity_suggestion == "high"
    assert result.final_severity == "not_assessed"
    assert result.cvss_vector is None
    assert result.independent_validation_required is True


def test_potential_impact_never_increases_severity():
    q, b, a, item, obs = make_inputs()
    result = assess_finding_impact(
        q, b, a, [claim(item, obs, verification="potential")]
    )
    assert result.assessment_status == "potential_impact_only"
    assert result.severity_suggestion == "not_assessed"
    assert result.demonstrated_dimensions == []


def test_unknown_scope_or_sensitivity_prevents_severity_suggestion():
    q, b, a, item, obs = make_inputs()
    result = assess_finding_impact(
        q, b, a, [claim(item, obs, scope="unknown")]
    )
    assert result.severity_suggestion == "not_assessed"
    assert "observed_impact_scope_or_asset_sensitivity_unknown" in result.blockers


def test_rejects_claim_linked_to_non_impact_or_unrelated_observation():
    q, b, a, item, obs = make_inputs()
    with pytest.raises(ValueError, match="observations"):
        assess_finding_impact(q, b, a, [claim(item, uuid4())])


def test_rejects_non_candidate_and_evidence_mismatch():
    q, b, a, item, obs = make_inputs()
    with pytest.raises(ValueError, match="human-review"):
        assess_finding_impact(q.model_copy(update={"qualification": "insufficient_evidence"}), b, a)
    q, b, a, item, obs = make_inputs()
    with pytest.raises(ValueError, match="evidence IDs"):
        assess_finding_impact(q.model_copy(update={"evidence_ids": []}), b, a)


def test_no_claims_never_infers_impact_from_free_text():
    q, b, a, item, obs = make_inputs()
    result = assess_finding_impact(q, b, a, [])
    assert result.assessment_status == "no_structured_impact_claims"
    assert result.severity_suggestion == "not_assessed"
    assert any("free-text impact was not interpreted." in item.lower() for item in result.rationale)
