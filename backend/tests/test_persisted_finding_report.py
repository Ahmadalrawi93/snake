import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.db.models import AIAnalysisRun, FindingCandidateRecord, Project, User
from app.schemas.analysis_context import AnalysisContext
from app.schemas.finding_qualification import FindingQualification
from app.schemas.validation_evidence import (
    ValidationEvidenceAssessment, ValidationEvidenceBundle, ValidationEvidenceItem,
)
from app.core import persisted_finding_report as service


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@pytest.fixture
def persisted_report_context(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine, autoflush=False)()
    owner = User(email="report-owner@example.org", password_hash="unused")
    other = User(email="report-other@example.org", password_hash="unused")
    db.add_all([owner, other])
    db.flush()
    project = Project(owner_id=owner.id, name="Report project")
    foreign_project = Project(owner_id=other.id, name="Foreign report project")
    db.add_all([project, foreign_project])
    db.flush()

    context = AnalysisContext(total_observations=0, unique_observations=0, duplicate_count=0, groups=[], ungrouped=[])
    context_sha = hashlib.sha256(canonical(context.model_dump(mode="json")).encode()).hexdigest()
    observation_id = uuid4()
    now = datetime.now(timezone.utc)
    items = [
        ValidationEvidenceItem(
            evidence_id=uuid4(), evidence_type="observed_behavior", relationship="supports",
            statement="The designated secondary test account received a protected synthetic record.",
            source_label="authorized test session", observation_ids=[observation_id],
            recorded_at=now, human_attested=True,
        ),
        ValidationEvidenceItem(
            evidence_id=uuid4(), evidence_type="expected_behavior", relationship="supports",
            statement="The documented policy states that only the owning test account may read this record.",
            source_label="program policy", observation_ids=[observation_id],
            recorded_at=now, human_attested=True,
        ),
        ValidationEvidenceItem(
            evidence_id=uuid4(), evidence_type="impact_context", relationship="supports",
            statement="The record contains synthetic order data created solely for this authorized test.",
            source_label="test fixture", observation_ids=[observation_id],
            recorded_at=now, human_attested=True,
        ),
        ValidationEvidenceItem(
            evidence_id=uuid4(), evidence_type="authorized_test_account", relationship="supports",
            statement="Two program-designated test identities were used.",
            source_label="test setup", observation_ids=[],
            recorded_at=now, human_attested=True,
        ),
    ]
    bundle = ValidationEvidenceBundle(
        strategy_id="idor_test", analysis_context_sha256=context_sha,
        items=items, reviewed_at=now,
    )
    qualification = FindingQualification(
        candidate_fingerprint="b" * 64, category="idor",
        title="Potential cross-account object access",
        qualification="human_review_candidate", evidence_quality="documented_consistent",
        impact_quality="documented_not_independently_verified", blockers=[],
        evidence_ids=[str(item.evidence_id) for item in items],
        observation_ids=[str(observation_id)],
    )
    strategy = {
        "plan_version": "1", "status": "review_required",
        "items": [{
            "strategy_id": "idor_test", "category": "object_authorization",
            "priority": "high", "priority_basis": "Test account boundary",
            "hypothesis": "Object authorization may be missing",
            "supporting_observation_ids": [str(observation_id)],
            "missing_evidence": [],
            "validation_questions": ["Can another test account read this record?"],
            "manual_review_actions": ["Compare authorized test-account access"],
            "prerequisites": [],
        }],
        "global_prerequisites": ["Use authorized test accounts"],
    }
    run = AIAnalysisRun(
        project_id=project.id, created_by=owner.id, context_sha256=context_sha,
        correlations_sha256="d" * 64, model="test-model",
        result_json=canonical({"validation_strategy": strategy}),
        execution_enabled=False,
    )
    db.add(run)
    db.flush()
    bundle_json = canonical(bundle.model_dump(mode="json"))
    candidate = FindingCandidateRecord(
        analysis_run_id=run.id, project_id=project.id, created_by=owner.id,
        candidate_fingerprint=qualification.candidate_fingerprint,
        qualification="human_review_candidate", finding_status="unconfirmed",
        evidence_bundle_sha256=hashlib.sha256(bundle_json.encode()).hexdigest(),
        evidence_bundle_json=bundle_json,
        qualification_json=canonical(qualification.model_dump(mode="json")),
        execution_enabled=False,
    )
    foreign_candidate = FindingCandidateRecord(
        analysis_run_id=run.id, project_id=foreign_project.id, created_by=other.id,
        candidate_fingerprint="f" * 64, qualification="human_review_candidate",
        finding_status="unconfirmed", evidence_bundle_sha256="0" * 64,
        evidence_bundle_json=bundle_json,
        qualification_json=canonical(qualification.model_copy(update={"candidate_fingerprint": "f" * 64}).model_dump(mode="json")),
        execution_enabled=False,
    )
    db.add_all([candidate, foreign_candidate])
    db.commit()

    evidence_assessment = ValidationEvidenceAssessment(
        strategy_id="idor_test", evidence_status="consistent",
        impact_status="documented_not_independently_verified", readiness="human_review_ready",
        supporting_evidence_count=4, contradicting_evidence_count=0, context_evidence_count=0,
        required_gaps=[], evidence_ids=[item.evidence_id for item in items],
        observation_ids=[observation_id],
    )
    monkeypatch.setattr(service, "load_verified_analysis_run_context", lambda _db, *, run: (context, None))
    monkeypatch.setattr(service, "assess_validation_evidence", lambda *_args, **_kwargs: evidence_assessment)
    yield db, owner, other, candidate, foreign_candidate
    db.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def test_builds_report_draft_from_verified_persisted_candidate(persisted_report_context):
    db, owner, _other, candidate, _foreign = persisted_report_context
    report, markdown = service.build_persisted_candidate_report(db, candidate_id=candidate.id, actor=owner)
    assert report.confirmation_status == "unconfirmed_human_review_draft"
    assert report.severity == "not_assessed"
    assert report.cvss_vector is None
    assert report.execution_enabled is False
    assert "Severity: Not assessed" in markdown
    assert "The designated secondary test account" in markdown


def test_report_draft_is_owner_scoped(persisted_report_context):
    db, _owner, other, candidate, foreign_candidate = persisted_report_context
    with pytest.raises(LookupError):
        service.build_persisted_candidate_report(db, candidate_id=candidate.id, actor=other)
    with pytest.raises(ValueError):
        service.build_persisted_candidate_report(db, candidate_id=foreign_candidate.id, actor=other)


def test_report_draft_rejects_tampered_evidence(persisted_report_context):
    db, owner, _other, candidate, _foreign = persisted_report_context
    candidate.evidence_bundle_json = "{}"
    db.commit()
    with pytest.raises(Exception):
        service.build_persisted_candidate_report(db, candidate_id=candidate.id, actor=owner)
