import base64
import hashlib
import os
import pytest
from cryptography.fernet import Fernet
from app.core.finding_lifecycle import (
    append_lifecycle_event, current_finding_status, store_evidence_artifact, read_evidence_artifact,
)
from app.schemas.finding_lifecycle import FindingLifecycleCreate, EvidenceArtifactCreate


def test_lifecycle_transition_is_append_only_and_requires_expected_state(db_session, user, finding_candidate):
    payload = FindingLifecycleCreate(expected_status="new", new_status="under_review", rationale="Begin manual review")
    event = append_lifecycle_event(db_session, candidate_id=finding_candidate.id, actor=user, payload=payload)
    db_session.commit()
    assert event.from_status == "new"
    assert current_finding_status(db_session, finding_candidate.id) == "under_review"
    with pytest.raises(ValueError):
        append_lifecycle_event(db_session, candidate_id=finding_candidate.id, actor=user,
            payload=FindingLifecycleCreate(expected_status="new", new_status="under_review", rationale="Stale transition"))


def test_terminal_status_cannot_be_reopened(db_session, user, finding_candidate):
    append_lifecycle_event(db_session, candidate_id=finding_candidate.id, actor=user,
        payload=FindingLifecycleCreate(expected_status="new", new_status="under_review", rationale="Review started"))
    append_lifecycle_event(db_session, candidate_id=finding_candidate.id, actor=user,
        payload=FindingLifecycleCreate(expected_status="under_review", new_status="rejected", rationale="Evidence disproved"))
    db_session.commit()
    with pytest.raises(ValueError):
        append_lifecycle_event(db_session, candidate_id=finding_candidate.id, actor=user,
            payload=FindingLifecycleCreate(expected_status="rejected", new_status="under_review", rationale="Reopen"))


def test_evidence_is_encrypted_and_integrity_checked(db_session, user, finding_candidate, monkeypatch):
    monkeypatch.setenv("SNAKE_EVIDENCE_VAULT_FERNET_KEY", Fernet.generate_key().decode())
    raw = b"authorized test evidence: HTTP response body"
    payload = EvidenceArtifactCreate(filename="../../response.txt", media_type="text/plain",
        content_base64=base64.b64encode(raw).decode(), description="Captured response")
    record = store_evidence_artifact(db_session, candidate_id=finding_candidate.id, actor=user, payload=payload)
    db_session.commit()
    assert record.filename == "response.txt"
    assert raw not in record.encrypted_content
    assert record.content_sha256 == hashlib.sha256(raw).hexdigest()
    loaded, content = read_evidence_artifact(db_session, artifact_id=record.id, actor=user)
    assert content == raw
    assert loaded.size_bytes == len(raw)


def test_vault_fails_closed_without_encryption_key(db_session, user, finding_candidate, monkeypatch):
    monkeypatch.delenv("SNAKE_EVIDENCE_VAULT_FERNET_KEY", raising=False)
    payload = EvidenceArtifactCreate(filename="proof.txt", media_type="text/plain",
        content_base64=base64.b64encode(b"proof").decode())
    with pytest.raises(RuntimeError):
        store_evidence_artifact(db_session, candidate_id=finding_candidate.id, actor=user, payload=payload)


def test_evidence_rejects_oversized_content(db_session, user, finding_candidate, monkeypatch):
    monkeypatch.setenv("SNAKE_EVIDENCE_VAULT_FERNET_KEY", Fernet.generate_key().decode())
    payload = EvidenceArtifactCreate(filename="large.bin", media_type="application/octet-stream",
        content_base64=base64.b64encode(b"x" * (1024 * 1024 + 1)).decode())
    with pytest.raises(ValueError):
        store_evidence_artifact(db_session, candidate_id=finding_candidate.id, actor=user, payload=payload)
