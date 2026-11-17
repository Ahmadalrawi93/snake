from datetime import datetime, timezone
from uuid import uuid4
import pytest
from app.core.finding_report import build_finding_report_draft, render_finding_report_markdown
from app.schemas.finding_qualification import FindingQualification
from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceItem, ValidationEvidenceAssessment

def make_inputs():
    obs=uuid4()
    items=[
        ValidationEvidenceItem(evidence_id=uuid4(),evidence_type="observed_behavior",relationship="supports",statement="The designated secondary test account received the protected test record.",source_label="authorized test session",observation_ids=[obs],recorded_at=datetime.now(timezone.utc),human_attested=True),
        ValidationEvidenceItem(evidence_id=uuid4(),evidence_type="expected_behavior",relationship="supports",statement="The documented policy states that only the owning test account may read this record.",source_label="program policy",observation_ids=[obs],recorded_at=datetime.now(timezone.utc),human_attested=True),
        ValidationEvidenceItem(evidence_id=uuid4(),evidence_type="impact_context",relationship="supports",statement="The record contains synthetic order data created solely for this authorized test.",source_label="test fixture",observation_ids=[obs],recorded_at=datetime.now(timezone.utc),human_attested=True),
        ValidationEvidenceItem(evidence_id=uuid4(),evidence_type="authorized_test_account",relationship="supports",statement="Two program-designated test identities were used.",source_label="test setup",observation_ids=[],recorded_at=datetime.now(timezone.utc),human_attested=True),
    ]
    bundle=ValidationEvidenceBundle(strategy_id="idor_test",analysis_context_sha256="a"*64,items=items,reviewed_at=datetime.now(timezone.utc))
    q=FindingQualification(candidate_fingerprint="b"*64,category="idor",title="Potential cross-account object access",qualification="human_review_candidate",evidence_quality="documented_consistent",impact_quality="documented_not_independently_verified",blockers=[],evidence_ids=[str(x.evidence_id) for x in items],observation_ids=[str(obs)])
    a=ValidationEvidenceAssessment(strategy_id="idor_test",evidence_status="consistent",impact_status="documented_not_independently_verified",readiness="human_review_ready",supporting_evidence_count=4,contradicting_evidence_count=0,context_evidence_count=0,required_gaps=[],evidence_ids=[x.evidence_id for x in items],observation_ids=[obs])
    return q,bundle,a

def test_builds_evidence_bound_unconfirmed_report():
    q,b,a=make_inputs()
    report=build_finding_report_draft(q,b,a)
    md=render_finding_report_markdown(report)
    assert report.confirmation_status=="unconfirmed_human_review_draft"
    assert report.severity=="not_assessed" and report.cvss_vector is None
    assert "The designated secondary test account" in md
    assert "Not assessed" in md

def test_rejects_non_candidate_and_mismatched_evidence():
    q,b,a=make_inputs()
    q=q.model_copy(update={"qualification":"insufficient_evidence"})
    with pytest.raises(ValueError):
        build_finding_report_draft(q,b,a)
    q,b,a=make_inputs()
    q=q.model_copy(update={"observation_ids":[]})
    with pytest.raises(ValueError):
        build_finding_report_draft(q,b,a)

def test_rejects_missing_impact_or_inconsistent_assessment():
    q,b,a=make_inputs()
    b=b.model_copy(update={"items":b.items[:-2]})
    q=q.model_copy(update={"evidence_ids":[str(x.evidence_id) for x in b.items],"observation_ids":[str(r) for x in b.items for r in x.observation_ids]})
    a=a.model_copy(update={"evidence_ids":[x.evidence_id for x in b.items],"observation_ids":[r for x in b.items for r in x.observation_ids]})
    with pytest.raises(ValueError):
        build_finding_report_draft(q,b,a)
