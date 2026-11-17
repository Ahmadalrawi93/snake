from datetime import datetime, timezone
from uuid import UUID
import pytest
from app.core.evidence_quality import assess_evidence_quality
from app.schemas.validation_evidence import ValidationEvidenceAssessment, ValidationEvidenceBundle, ValidationEvidenceItem

def make_item(n, source, relation="supports", statement=None, refs=None):
    return ValidationEvidenceItem(
        evidence_id=UUID(f"00000000-0000-4000-8000-{n:012d}"),
        evidence_type="observed_behavior", relationship=relation,
        statement=statement or f"Observed authorized behavior record {n}",
        source_label=source, observation_ids=refs or [UUID("00000000-0000-4000-8000-000000000099")],
        recorded_at=datetime.now(timezone.utc), human_attested=True)

def make_bundle(items):
    return ValidationEvidenceBundle(strategy_id="auth_strategy", analysis_context_sha256="a"*64,
        items=items, reviewed_at=datetime.now(timezone.utc))

def assess(b):
    return ValidationEvidenceAssessment(strategy_id=b.strategy_id, evidence_status="mixed" if any(x.relationship=="contradicts" for x in b.items) else "consistent",
        impact_status="not_documented", readiness="more_evidence_required",
        supporting_evidence_count=sum(x.relationship=="supports" for x in b.items),
        contradicting_evidence_count=sum(x.relationship=="contradicts" for x in b.items),
        context_evidence_count=sum(x.relationship=="context_only" for x in b.items), required_gaps=[],
        evidence_ids=[x.evidence_id for x in b.items],
        observation_ids=sorted({r for x in b.items for r in x.observation_ids}, key=str))

def test_multiple_labels_are_not_claimed_as_verified_independence():
    b=make_bundle([make_item(1,"source-a"),make_item(2,"source-b", statement="Different authorized record from source B")])
    result=assess_evidence_quality(b,assess(b))
    assert result.independent_source_count == 2
    assert result.source_independence == "multiple_labeled_sources_unverified"
    assert result.source_independence_verified is False

def test_repeated_records_and_shared_observations_are_flagged():
    b=make_bundle([make_item(1,"reviewer", statement="Same captured authorized observation record"),make_item(2,"reviewer", statement="Same captured authorized observation record")])
    result=assess_evidence_quality(b,assess(b))
    assert result.repeated_evidence_groups == 1
    assert result.observation_overlap_groups == 1
    assert result.quality_band == "limited"

def test_contradictions_remain_visible_and_lower_quality():
    b=make_bundle([make_item(1,"source-a"),make_item(2,"source-b","contradicts",statement="Contradictory authorized observation record")])
    result=assess_evidence_quality(b,assess(b))
    assert result.contradicting_count == 1
    assert "contradictory_evidence_requires_human_resolution" in result.warnings
    assert result.quality_band == "limited"

def test_rejects_detached_assessment_counts():
    b=make_bundle([make_item(1,"reviewer")])
    forged=assess(b).model_copy(update={"supporting_evidence_count":99})
    with pytest.raises(ValueError,match="supporting_evidence_count"):
        assess_evidence_quality(b,forged)
