import base64
import hashlib
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db.database import Base
from app.db.models import User, Project, AIAnalysisRun, FindingCandidateRecord, HumanFindingDecision
from app.core.finding_lifecycle import (
    append_lifecycle_event, current_finding_status, store_evidence_artifact, read_evidence_artifact,
)
from app.schemas.finding_lifecycle import FindingLifecycleCreate, EvidenceArtifactCreate


@pytest.fixture
def vault_context():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    user = User(email="vault@example.org", password_hash="not-used")
    session.add(user)
    session.flush()
    project = Project(owner_id=user.id, name="Evidence Lab")
    session.add(project)
    session.flush()
    run = AIAnalysisRun(
        project_id=project.id, created_by=user.id, context_sha256="a" * 64,
        correlations_sha256="b" * 64, model="test-model", result_json="{}",
        execution_enabled=False,
    )
    session.add(run)
    session.flush()
    candidate = FindingCandidateRecord(
        analysis_run_id=run.id, project_id=project.id, created_by=user.id,
        candidate_fingerprint="c" * 64, qualification="human_review_candidate",
        finding_status="unconfirmed", evidence_bundle_sha256="d" * 64,
        evidence_bundle_json="{}", qualification_json="{}", execution_enabled=False,
    )
    session.add(candidate)
    session.commit()
    yield session, user, candidate
    session.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def test_lifecycle_transition_is_append_only_and_requires_expected_state(vault_context):
    db, user, candidate = vault_context
    payload = FindingLifecycleCreate(expected_status="new", new_status="under_review", rationale="Begin manual review")
    event = append_lifecycle_event(db, candidate_id=candidate.id, actor=user, payload=payload)
    db.commit()
    assert event.from_status == "new"
    assert current_finding_status(db, candidate.id) == "under_review"
    with pytest.raises(ValueError):
        append_lifecycle_event(db, candidate_id=candidate.id, actor=user,
            payload=FindingLifecycleCreate(expected_status="new", new_status="under_review", rationale="Stale transition"))


def test_terminal_status_cannot_be_reopened(vault_context):
    db, user, candidate = vault_context
    append_lifecycle_event(db, candidate_id=candidate.id, actor=user,
        payload=FindingLifecycleCreate(expected_status="new", new_status="under_review", rationale="Review started"))
    db.add(HumanFindingDecision(
        analysis_run_id=candidate.analysis_run_id, project_id=candidate.project_id,
        evaluator_id=user.id, candidate_fingerprint=candidate.candidate_fingerprint,
        outcome="false_positive", evidence_sha256="e" * 64,
        validation_method="manual_reproduction", notes="", reviewer_attested=True,
    ))
    db.flush()
    append_lifecycle_event(db, candidate_id=candidate.id, actor=user,
        payload=FindingLifecycleCreate(expected_status="under_review", new_status="rejected", rationale="Evidence disproved"))
    db.commit()
    with pytest.raises(ValueError):
        append_lifecycle_event(db, candidate_id=candidate.id, actor=user,
            payload=FindingLifecycleCreate(expected_status="rejected", new_status="under_review", rationale="Reopen"))


def test_evidence_is_encrypted_and_integrity_checked(vault_context, monkeypatch):
    db, user, candidate = vault_context
    monkeypatch.setenv("SNAKE_EVIDENCE_VAULT_FERNET_KEY", Fernet.generate_key().decode())
    raw = b"authorized test evidence: HTTP response body"
    payload = EvidenceArtifactCreate(filename="../../response.txt", media_type="text/plain",
        content_base64=base64.b64encode(raw).decode(), description="Captured response")
    record = store_evidence_artifact(db, candidate_id=candidate.id, actor=user, payload=payload)
    db.commit()
    assert record.filename == "response.txt"
    assert raw not in record.encrypted_content
    assert record.content_sha256 == hashlib.sha256(raw).hexdigest()
    loaded, content = read_evidence_artifact(db, artifact_id=record.id, actor=user)
    assert content == raw
    assert loaded.size_bytes == len(raw)


def test_vault_fails_closed_without_encryption_key(vault_context, monkeypatch):
    db, user, candidate = vault_context
    monkeypatch.delenv("SNAKE_EVIDENCE_VAULT_FERNET_KEY", raising=False)
    payload = EvidenceArtifactCreate(filename="proof.txt", media_type="text/plain",
        content_base64=base64.b64encode(b"proof").decode())
    with pytest.raises(RuntimeError):
        store_evidence_artifact(db, candidate_id=candidate.id, actor=user, payload=payload)


def test_evidence_rejects_oversized_content(vault_context, monkeypatch):
    db, user, candidate = vault_context
    monkeypatch.setenv("SNAKE_EVIDENCE_VAULT_FERNET_KEY", Fernet.generate_key().decode())
    payload = EvidenceArtifactCreate(filename="large.bin", media_type="application/octet-stream",
        content_base64=base64.b64encode(b"x" * (1024 * 1024 + 1)).decode())
    with pytest.raises(ValueError):
        store_evidence_artifact(db, candidate_id=candidate.id, actor=user, payload=payload)


def test_evidence_filename_rejects_header_control_characters():
    with pytest.raises(ValueError):
        EvidenceArtifactCreate(
            filename="proof.txt\r\nX-Injected: yes",
            media_type="text/plain",
            content_base64=base64.b64encode(b"proof").decode(),
        )
