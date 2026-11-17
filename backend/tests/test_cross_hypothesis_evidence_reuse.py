from datetime import datetime, timezone
from uuid import UUID
import pytest
from app.core.cross_hypothesis_evidence_reuse import build_evidence_reuse_report
from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceItem
from app.schemas.validation_strategy import ValidationStrategyItem, ValidationStrategyPlan

def strat(sid, obs):
    return ValidationStrategyItem(strategy_id=sid,category="object_authorization",priority="medium",
        priority_basis="Review",hypothesis="Review authorized object access",
        supporting_observation_ids=obs,missing_evidence=[],validation_questions=["Review access policy"],
        manual_review_actions=["Review approved records"],prerequisites=[])

def bundle(sid, refs):
    return ValidationEvidenceBundle(strategy_id=sid,analysis_context_sha256="a"*64,reviewed_at=datetime.now(timezone.utc),
        items=[ValidationEvidenceItem(evidence_id=UUID(f"00000000-0000-4000-8000-{i:012d}"),
            evidence_type="observed_behavior",relationship="supports",statement=f"Authorized observed behavior evidence {i}",
            source_label="reviewer supplied record",observation_ids=[UUID(ref)],recorded_at=datetime.now(timezone.utc),
            human_attested=True) for i,ref in enumerate(refs,1)])

def test_reports_shared_observations_and_unique_evidence():
    refs=["00000000-0000-4000-8000-000000000001","00000000-0000-4000-8000-000000000002"]
    p=ValidationStrategyPlan(items=[strat("current_review",refs),strat("sibling_review",[refs[0],"00000000-0000-4000-8000-000000000003"])],global_prerequisites=["Written authorization"])
    r=build_evidence_reuse_report(p,bundle("current_review",refs))
    assert r.reused_with_other_hypotheses[0].shared_observation_count == 1
    assert r.unique_observation_count == 1
    assert r.reused_with_other_hypotheses[0].interpretation == "partial_reuse"
    assert r.execution_enabled is False

def test_rejects_bundle_not_in_plan():
    p=ValidationStrategyPlan(items=[strat("other_review",["obs"])],global_prerequisites=["Written authorization"])
    with pytest.raises(ValueError,match="not present"):
        build_evidence_reuse_report(p,bundle("missing_review",["00000000-0000-4000-8000-000000000001"]))
