import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.db.models import (
    AIAnalysisRun, AuditEvent, FindingCandidateRecord, FindingImpactAssessmentRecord,
    Project, User,
)
from app.schemas.analysis_context import AnalysisContext
from app.schemas.finding_impact import FindingImpactClaim
from app.schemas.finding_qualification import FindingQualification
from app.schemas.validation_evidence import (
    ValidationEvidenceAssessment, ValidationEvidenceBundle, ValidationEvidenceItem,
)
from app.core import persisted_finding_impact as service


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@pytest.fixture
def impact_context(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine, autoflush=False)()
    user = User(email="impact-owner@example.org", password_hash="unused")
    other = User(email="impact-other@example.org", password_hash="unused")
    db.add_all([user, other])
    db.flush()
    project = Project(owner_id=user.id, name="Impact Lab")
    other_project = Project(owner_id=other.id, name="Other Lab")
    db.add_all([project, other_project])
    db.flush()

    context = AnalysisContext(
        total_observations=0, unique_observations=0, duplicate_count=0,
        groups=[], ungrouped=[],
    )
    context_digest = hashlib.sha256(canonical(context.model_dump(mode="json")).encode()).hexdigest()
    obs = uuid4()
    evidence = ValidationEvidenceItem(
        evidence_id=uuid4(), evidence_type="impact_context", relationship="supports",
        statement="A second authorized test identity accessed synthetic records.",
        source_label="manual authorized validation", observation_ids=[obs],
        recorded_at=datetime.now(timezone.utc), human_attested=True,
    )
    bundle = ValidationEvidenceBundle(
        strategy_id="idor_test", analysis_context_sha256=context_digest,
        items=[evidence], reviewed_at=datetime.now(timezone.utc),
    )
    qualification = FindingQualification(
        candidate_fingerprint="c" * 64, category="idor",
        title="Cross-account object access", qualification="human_review_candidate",
        evidence_quality="documented_consistent",
        impact_quality="documented_not_independently_verified", blockers=[],
        evidence_ids=[str(evidence.evidence_id)], observation_ids=[str(obs)],
    )
    bundle_json = canonical(bundle.model_dump(mode="json"))
    run = AIAnalysisRun(
        project_id=project.id, created_by=user.id, context_sha256=context_digest,
        correlations_sha256="d" * 64, model="test-model",
        result_json=canonical({"validation_strategy": {
            "plan_version": "1", "status": "review_required",
            "items": [{
                "strategy_id": "idor_test", "category": "object_authorization",
                "priority": "high", "priority_basis": "Test account boundary",
                "hypothesis": "Object authorization may be missing",
                "supporting_observation_ids": [str(obs)], "missing_evidence": [],
                "validation_questions": ["Can another test account read this record?"],
                "manual_review_actions": ["Compare authorized test-account access"],
                "prerequisites": [],
            }],
            "global_prerequisites": ["Use authorized test accounts"],
        }}),
        execution_enabled=False,
    )
    db.add(run)
    db.flush()
    candidate = FindingCandidateRecord(
        analysis_run_id=run.id, project_id=project.id, created_by=user.id,
        candidate_fingerprint=qualification.candidate_fingerprint,
        qualification="human_review_candidate", finding_status="unconfirmed",
        evidence_bundle_sha256=hashlib.sha256(bundle_json.encode()).hexdigest(),
        evidence_bundle_json=bundle_json,
        qualification_json=canonical(qualification.model_dump(mode="json")),
        execution_enabled=False,
    )
    foreign_run = AIAnalysisRun(
        project_id=other_project.id, created_by=other.id,
        context_sha256=context_digest, correlations_sha256="e" * 64,
        model="test-model", result_json="{}", execution_enabled=False,
    )
    db.add(foreign_run)
    db.flush()
    foreign_candidate = FindingCandidateRecord(
        analysis_run_id=foreign_run.id, project_id=other_project.id, created_by=other.id,
        candidate_fingerprint="f" * 64, qualification="human_review_candidate",
        finding_status="unconfirmed", evidence_bundle_sha256="a" * 64,
        evidence_bundle_json=bundle_json,
        qualification_json=canonical(qualification.model_copy(update={
            "candidate_fingerprint": "f" * 64
        }).model_dump(mode="json")),
        execution_enabled=False,
    )
    db.add_all([candidate, foreign_candidate])
    db.commit()

    evidence_assessment = ValidationEvidenceAssessment(
        strategy_id="idor_test", evidence_status="consistent",
        impact_status="documented_not_independently_verified",
        readiness="human_review_ready", supporting_evidence_count=1,
        contradicting_evidence_count=0, context_evidence_count=0,
        required_gaps=[], evidence_ids=[evidence.evidence_id],
        observation_ids=[obs],
    )
    monkeypatch.setattr(
        service, "load_verified_analysis_run_context",
        lambda _db, *, run: (context, None),
    )
    monkeypatch.setattr(
        service, "assess_validation_evidence",
        lambda *_args, **_kwargs: evidence_assessment,
    )
    claim = FindingImpactClaim(
        evidence_id=evidence.evidence_id, observation_ids=[obs],
        dimension="confidentiality", level="high", verification="observed",
        scope="multiple_records", data_sensitivity="sensitive_data",
        statement="A second test identity read protected synthetic records.",
        human_attested=True,
    )
    yield db, user, other, candidate, foreign_candidate, claim
    db.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def test_persisted_assessment_is_owner_scoped_and_evidence_bound(impact_context):
    db, owner, _other, candidate, _foreign, claim = impact_context
    result = service.create_persisted_finding_impact(
        db, candidate_id=candidate.id, actor=owner, claims=[claim],
    )
    db.commit()
    assert result["candidate_id"] == candidate.id
    assert result["evidence_bundle_sha256"] == candidate.evidence_bundle_sha256
    assert result["assessment"]["severity_suggestion"] == "high"
    assert result["assessment"]["final_severity"] == "not_assessed"
    assert result["final_severity"] == "not_assessed"
    assert result["cvss_vector"] is None
    assert result["execution_enabled"] is False
    assert db.query(AuditEvent).filter_by(
        action="finding_impact_assessment.recorded"
    ).count() == 1


def test_same_assessment_is_idempotent_and_different_claims_append(impact_context):
    db, owner, _other, candidate, _foreign, claim = impact_context
    first = service.create_persisted_finding_impact(
        db, candidate_id=candidate.id, actor=owner, claims=[claim],
    )
    db.commit()
    repeated = service.create_persisted_finding_impact(
        db, candidate_id=candidate.id, actor=owner, claims=[claim],
    )
    db.commit()
    assert repeated["id"] == first["id"]
    assert db.query(FindingImpactAssessmentRecord).filter_by(
        candidate_id=candidate.id
    ).count() == 1



def test_distinct_claim_revision_is_appended_not_overwritten(impact_context):
    db, owner, _other, candidate, _foreign, claim = impact_context
    first = service.create_persisted_finding_impact(
        db, candidate_id=candidate.id, actor=owner, claims=[claim],
    )
    db.commit()
    revised_claim = claim.model_copy(update={
        "statement": "A second authorized test identity accessed additional synthetic records."
    })
    second = service.create_persisted_finding_impact(
        db, candidate_id=candidate.id, actor=owner, claims=[revised_claim],
    )
    db.commit()
    assert second["id"] != first["id"]
    assert db.query(FindingImpactAssessmentRecord).filter_by(
        candidate_id=candidate.id
    ).count() == 2


def test_other_owner_cannot_read_or_create_assessments(impact_context):
    db, owner, other, candidate, foreign_candidate, claim = impact_context
    with pytest.raises(LookupError):
        service.create_persisted_finding_impact(
            db, candidate_id=candidate.id, actor=other, claims=[claim],
        )
    with pytest.raises(LookupError):
        service.list_persisted_finding_impacts(
            db, candidate_id=candidate.id, actor=other,
        )
    with pytest.raises(LookupError):
        service.create_persisted_finding_impact(
            db, candidate_id=foreign_candidate.id, actor=owner, claims=[claim],
        )

def test_impact_api_create_and_read_round_trip(impact_context):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.api.dependencies import get_current_user
    from app.db.database import get_db

    db, owner, _other, candidate, _foreign, claim = impact_context

    def override_db():
        yield db

    app.dependency_overrides[get_current_user] = lambda: owner
    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/finding-candidates/{candidate.id}/impact-assessments",
                json={"claims": [claim.model_dump(mode="json")]},
            )
            assert response.status_code == 201, response.text
            created = response.json()
            assert created["candidate_id"] == candidate.id
            assert created["final_severity"] == "not_assessed"
            assert created["cvss_vector"] is None
            assert created["execution_enabled"] is False

            listed = client.get(
                f"/api/v1/finding-candidates/{candidate.id}/impact-assessments"
            )
            assert listed.status_code == 200, listed.text
            assert len(listed.json()) == 1
            assert listed.json()[0]["id"] == created["id"]
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)


def test_impact_api_rejects_foreign_owner(impact_context):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.api.dependencies import get_current_user
    from app.db.database import get_db

    db, _owner, other, candidate, _foreign, _claim = impact_context

    def override_db():
        yield db

    app.dependency_overrides[get_current_user] = lambda: other
    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            response = client.get(
                f"/api/v1/finding-candidates/{candidate.id}/impact-assessments"
            )
            assert response.status_code == 404
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)

