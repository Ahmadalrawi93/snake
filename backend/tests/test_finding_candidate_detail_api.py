import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.dependencies import get_current_user
from app.db.database import Base, get_db
from app.db.models import AIAnalysisRun, FindingCandidateRecord, Project, User
from app.main import app


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@pytest.fixture
def candidate_detail_context():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    db = Session()

    owner = User(email="candidate-detail-owner@example.org", password_hash="unused")
    other = User(email="candidate-detail-other@example.org", password_hash="unused")
    db.add_all([owner, other])
    db.flush()
    project = Project(owner_id=owner.id, name="Candidate Detail")
    foreign_project = Project(owner_id=other.id, name="Foreign Project")
    db.add_all([project, foreign_project])
    db.flush()

    context_sha = "a" * 64
    run = AIAnalysisRun(
        project_id=project.id,
        created_by=owner.id,
        context_sha256=context_sha,
        correlations_sha256="b" * 64,
        model="test-model",
        result_json="{}",
        execution_enabled=False,
    )
    db.add(run)
    db.flush()

    evidence_id = str(uuid4())
    observation_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    qualification = {
        "candidate_fingerprint": "c" * 64,
        "category": "object_authorization",
        "title": "Cross-account object access",
        "qualification": "human_review_candidate",
        "evidence_quality": "documented_consistent",
        "impact_quality": "documented_not_independently_verified",
        "duplicate_of_fingerprint": None,
        "blockers": [],
        "evidence_ids": [evidence_id],
        "observation_ids": [observation_id],
        "disposition": "unconfirmed_candidate_requires_human_decision",
        "finding_status": "unconfirmed",
        "execution_enabled": False,
    }
    bundle = {
        "strategy_id": "idor_test",
        "analysis_context_sha256": context_sha,
        "items": [{
            "evidence_id": evidence_id,
            "evidence_type": "impact_context",
            "relationship": "supports",
            "statement": "A second authorized test identity accessed a synthetic record.",
            "source_label": "manual authorized validation",
            "observation_ids": [observation_id],
            "recorded_at": now,
            "human_attested": True,
        }],
        "reviewer_note": "Manual review",
        "reviewed_at": now,
    }
    bundle_json = canonical(bundle)
    candidate = FindingCandidateRecord(
        analysis_run_id=run.id,
        project_id=project.id,
        created_by=owner.id,
        candidate_fingerprint="c" * 64,
        qualification="human_review_candidate",
        finding_status="unconfirmed",
        evidence_bundle_sha256=hashlib.sha256(bundle_json.encode()).hexdigest(),
        evidence_bundle_json=bundle_json,
        qualification_json=canonical(qualification),
        execution_enabled=False,
    )
    db.add(candidate)
    db.commit()

    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: owner
    try:
        yield db, owner, other, candidate
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_candidate_detail_returns_validated_immutable_evidence(candidate_detail_context):
    _db, _owner, _other, candidate = candidate_detail_context
    with TestClient(app) as client:
        response = client.get(f"/api/v1/finding-candidates/{candidate.id}")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["candidate_fingerprint"] == "c" * 64
    assert payload["qualification"]["title"] == "Cross-account object access"
    assert payload["evidence_bundle"]["items"][0]["evidence_type"] == "impact_context"
    assert payload["evidence_bundle_sha256"] == candidate.evidence_bundle_sha256
    assert payload["execution_enabled"] is False


def test_candidate_detail_is_owner_scoped(candidate_detail_context):
    _db, _owner, other, candidate = candidate_detail_context
    app.dependency_overrides[get_current_user] = lambda: other
    try:
        with TestClient(app) as client:
            response = client.get(f"/api/v1/finding-candidates/{candidate.id}")
        assert response.status_code == 404
    finally:
        app.dependency_overrides[get_current_user] = lambda: _owner


def test_candidate_detail_detects_tampered_evidence(candidate_detail_context):
    db, _owner, _other, candidate = candidate_detail_context
    candidate.evidence_bundle_json = "{}"
    db.commit()
    with TestClient(app) as client:
        response = client.get(f"/api/v1/finding-candidates/{candidate.id}")
    assert response.status_code == 409


def test_candidate_detail_rejects_context_mismatch(candidate_detail_context):
    db, _owner, _other, candidate = candidate_detail_context
    bundle = json.loads(candidate.evidence_bundle_json)
    bundle["analysis_context_sha256"] = "d" * 64
    candidate.evidence_bundle_json = canonical(bundle)
    candidate.evidence_bundle_sha256 = hashlib.sha256(
        candidate.evidence_bundle_json.encode()
    ).hexdigest()
    db.commit()
    with TestClient(app) as client:
        response = client.get(f"/api/v1/finding-candidates/{candidate.id}")
    assert response.status_code == 409


def test_candidate_detail_rejects_qualification_evidence_mismatch(candidate_detail_context):
    db, _owner, _other, candidate = candidate_detail_context
    qualification = json.loads(candidate.qualification_json)
    qualification["evidence_ids"] = []
    candidate.qualification_json = canonical(qualification)
    db.commit()
    with TestClient(app) as client:
        response = client.get(f"/api/v1/finding-candidates/{candidate.id}")
    assert response.status_code == 409


def test_candidate_similarity_returns_empty_for_single_candidate(candidate_detail_context):
    _db, _owner, _other, candidate = candidate_detail_context
    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/projects/{candidate.project_id}/finding-candidates/{candidate.id}/similarity"
        )
    assert response.status_code == 200, response.text
    assert response.json() == []


def test_candidate_similarity_rejects_tampered_candidate_evidence(candidate_detail_context):
    db, _owner, _other, candidate = candidate_detail_context
    candidate.evidence_bundle_json = "{}"
    db.commit()
    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/projects/{candidate.project_id}/finding-candidates/{candidate.id}/similarity"
        )
    assert response.status_code == 409
