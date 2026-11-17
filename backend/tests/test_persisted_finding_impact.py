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
from app.core.finding_impact_guards import install_sqlite_finding_impact_guards


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@pytest.fixture
def impact_context(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        install_sqlite_finding_impact_guards(connection)
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
    assert db.query(AuditEvent).filter_by(
        action="finding_impact_assessment.recorded"
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

def test_persisted_assessment_rejects_direct_update_and_delete(impact_context):
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    db, owner, _other, candidate, _foreign, claim = impact_context
    record = service.create_persisted_finding_impact(
        db, candidate_id=candidate.id, actor=owner, claims=[claim],
    )
    db.commit()
    record_id = record["id"]

    with pytest.raises(IntegrityError):
        db.execute(
            text("UPDATE finding_impact_assessments SET assessment_json = '{}' WHERE id = :id"),
            {"id": record_id},
        )
        db.commit()
    db.rollback()

    with pytest.raises(IntegrityError):
        db.execute(
            text("DELETE FROM finding_impact_assessments WHERE id = :id"),
            {"id": record_id},
        )
        db.commit()
    db.rollback()

    assert db.query(FindingImpactAssessmentRecord).filter_by(id=record_id).count() == 1




def test_database_constraints_keep_assessment_non_final_and_non_executable(impact_context):
    from sqlalchemy.exc import IntegrityError

    db, owner, _other, candidate, _foreign, claim = impact_context
    record = service.create_persisted_finding_impact(
        db, candidate_id=candidate.id, actor=owner, claims=[claim],
    )
    db.commit()

    base_values = {
        "candidate_id": candidate.id,
        "analysis_run_id": record["analysis_run_id"],
        "project_id": candidate.project_id,
        "reviewer_id": owner.id,
        "evidence_bundle_sha256": candidate.evidence_bundle_sha256,
        "claims_sha256": "1" * 64,
        "assessment_sha256": "2" * 64,
        "assessment_json": "{}",
        "created_at": record["created_at"],
    }
    invalid_values = [
        {"final_severity": "high", "cvss_vector": None, "execution_enabled": False},
        {"final_severity": "not_assessed", "cvss_vector": "CVSS:3.1/AV:N", "execution_enabled": False},
        {"final_severity": "not_assessed", "cvss_vector": None, "execution_enabled": True},
    ]
    for index, invalid in enumerate(invalid_values, start=3):
        values = dict(base_values)
        values["claims_sha256"] = str(index) * 64
        values["assessment_sha256"] = str(index + 1) * 64
        values.update(invalid)
        with pytest.raises(IntegrityError):
            db.add(FindingImpactAssessmentRecord(**values))
            db.flush()
        db.rollback()

    assert db.query(FindingImpactAssessmentRecord).filter_by(id=record["id"]).count() == 1



def test_impact_api_rejects_more_than_100_claims_without_persisting(impact_context):
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
                json={"claims": [claim.model_dump(mode="json")] * 101},
            )
            assert response.status_code == 422
            assert db.query(FindingImpactAssessmentRecord).filter_by(
                candidate_id=candidate.id
            ).count() == 0
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)



def test_impact_api_rejects_empty_claim_list_without_persisting(impact_context):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.api.dependencies import get_current_user
    from app.db.database import get_db

    db, owner, _other, candidate, _foreign, _claim = impact_context

    def override_db():
        yield db

    app.dependency_overrides[get_current_user] = lambda: owner
    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            response = client.post(
                f"/api/v1/finding-candidates/{candidate.id}/impact-assessments",
                json={"claims": []},
            )
            assert response.status_code == 422
            assert db.query(FindingImpactAssessmentRecord).filter_by(
                candidate_id=candidate.id
            ).count() == 0
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)



def test_persisted_impact_rejects_tampered_evidence_bundle(impact_context):
    db, owner, _other, candidate, _foreign, claim = impact_context
    payload = json.loads(candidate.evidence_bundle_json)
    payload["items"][0]["statement"] = "Changed after candidate persistence."
    candidate.evidence_bundle_json = canonical(payload)
    db.flush()

    with pytest.raises(ValueError, match="evidence bundle digest mismatch"):
        service.create_persisted_finding_impact(
            db, candidate_id=candidate.id, actor=owner, claims=[claim],
        )
    assert db.query(FindingImpactAssessmentRecord).filter_by(
        candidate_id=candidate.id
    ).count() == 0


def test_persisted_impact_rejects_candidate_qualification_binding_mismatch(impact_context):
    db, owner, _other, candidate, _foreign, claim = impact_context
    payload = json.loads(candidate.qualification_json)
    payload["candidate_fingerprint"] = "9" * 64
    candidate.qualification_json = canonical(payload)
    db.flush()

    with pytest.raises(ValueError, match="qualification binding mismatch"):
        service.create_persisted_finding_impact(
            db, candidate_id=candidate.id, actor=owner, claims=[claim],
        )
    assert db.query(FindingImpactAssessmentRecord).filter_by(
        candidate_id=candidate.id
    ).count() == 0


def test_persisted_impact_rejects_verified_context_digest_mismatch(impact_context, monkeypatch):
    db, owner, _other, candidate, _foreign, claim = impact_context
    changed_context = AnalysisContext(
        total_observations=1, unique_observations=1, duplicate_count=0,
        groups=[], ungrouped=[],
    )
    monkeypatch.setattr(
        service, "load_verified_analysis_run_context",
        lambda _db, *, run: (changed_context, None),
    )

    with pytest.raises(ValueError, match="context digest mismatch"):
        service.create_persisted_finding_impact(
            db, candidate_id=candidate.id, actor=owner, claims=[claim],
        )
    assert db.query(FindingImpactAssessmentRecord).filter_by(
        candidate_id=candidate.id
    ).count() == 0



def test_read_rejects_tampered_persisted_assessment_digest(impact_context):
    from sqlalchemy import text

    db, owner, _other, candidate, _foreign, claim = impact_context
    record = service.create_persisted_finding_impact(
        db, candidate_id=candidate.id, actor=owner, claims=[claim],
    )
    db.commit()

    payload = record["assessment"]
    payload["rationale"].append("Tampered after persistence.")
    db.execute(text("DROP TRIGGER finding_impact_assessments_no_update"))
    db.execute(
        text("UPDATE finding_impact_assessments SET assessment_json = :value WHERE id = :id"),
        {"value": canonical(payload), "id": record["id"]},
    )
    db.commit()

    with pytest.raises(ValueError, match="assessment digest mismatch"):
        service.list_persisted_finding_impacts(
            db, candidate_id=candidate.id, actor=owner,
        )


def test_read_rejects_claim_digest_mismatch_even_if_assessment_digest_matches(impact_context):
    from sqlalchemy import text

    db, owner, _other, candidate, _foreign, claim = impact_context
    record = service.create_persisted_finding_impact(
        db, candidate_id=candidate.id, actor=owner, claims=[claim],
    )
    db.commit()

    payload = record["assessment"]
    payload["claims"][0]["statement"] = "Modified human attestation statement."
    assessment_json = canonical(payload)
    assessment_digest = hashlib.sha256(assessment_json.encode()).hexdigest()
    db.execute(text("DROP TRIGGER finding_impact_assessments_no_update"))
    db.execute(
        text(
            "UPDATE finding_impact_assessments "
            "SET assessment_json = :value, assessment_sha256 = :digest WHERE id = :id"
        ),
        {"value": assessment_json, "digest": assessment_digest, "id": record["id"]},
    )
    db.commit()

    with pytest.raises(ValueError, match="claims digest mismatch"):
        service.list_persisted_finding_impacts(
            db, candidate_id=candidate.id, actor=owner,
        )
