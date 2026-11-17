from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.worker_protocol import WorkerTaskEnvelope, ensure_not_expired


def valid_payload():
    now = datetime.now(timezone.utc)
    return {
        "task_id": uuid4(),
        "job_id": 7,
        "scope_snapshot_id": 3,
        "scope_snapshot_sha256": "a" * 64,
        "profile": "passive_recon",
        "target_url": "https://example.org",
        "issued_at": now,
        "expires_at": now + timedelta(minutes=2),
        "execution_enabled": False,
    }


def test_worker_envelope_accepts_only_fixed_non_executable_contract():
    task = WorkerTaskEnvelope.model_validate(valid_payload())
    assert task.execution_enabled is False
    assert task.profile == "passive_recon"


def test_worker_envelope_rejects_arbitrary_shell_command():
    payload = valid_payload()
    payload["command"] = "curl https://attacker.invalid"
    with pytest.raises(ValidationError):
        WorkerTaskEnvelope.model_validate(payload)


def test_worker_envelope_rejects_execution_enabled():
    payload = valid_payload()
    payload["execution_enabled"] = True
    with pytest.raises(ValidationError):
        WorkerTaskEnvelope.model_validate(payload)


def test_worker_envelope_rejects_unknown_profile_and_naive_time():
    payload = valid_payload()
    payload["profile"] = "active_exploit"
    with pytest.raises(ValidationError):
        WorkerTaskEnvelope.model_validate(payload)
    payload = valid_payload()
    payload["issued_at"] = datetime.now()
    with pytest.raises(ValidationError):
        WorkerTaskEnvelope.model_validate(payload)


def test_expired_worker_task_is_rejected():
    task = WorkerTaskEnvelope.model_validate(valid_payload())
    future = task.expires_at + timedelta(seconds=1)
    with pytest.raises(ValueError, match="expired"):
        ensure_not_expired(task, now=future)


def test_worker_task_rejects_issue_time_too_far_in_future():
    payload = valid_payload()
    payload["issued_at"] = datetime.now(timezone.utc) + timedelta(minutes=1)
    task = WorkerTaskEnvelope.model_validate(payload)
    with pytest.raises(ValueError, match="issue time is in the future"):
        ensure_not_expired(task, now=datetime.now(timezone.utc))


def test_worker_task_rejects_lifetime_over_five_minutes():
    payload = valid_payload()
    payload["expires_at"] = payload["issued_at"] + timedelta(seconds=301)
    task = WorkerTaskEnvelope.model_validate(payload)
    with pytest.raises(ValueError, match="lifetime exceeds 300 seconds"):
        ensure_not_expired(task, now=payload["issued_at"])


def test_worker_task_accepts_lifetime_at_five_minute_boundary():
    payload = valid_payload()
    payload["expires_at"] = payload["issued_at"] + timedelta(seconds=300)
    task = WorkerTaskEnvelope.model_validate(payload)
    ensure_not_expired(task, now=payload["issued_at"])


def test_worker_envelope_binds_approved_scope_manifest():
    payload = valid_payload()
    payload["approved_scope_rules"] = ["example.org", "*.example.org"]
    task = WorkerTaskEnvelope.model_validate(payload)
    assert task.approved_scope_rules == ["example.org", "*.example.org"]


def test_worker_envelope_rejects_target_outside_signed_scope_manifest():
    payload = valid_payload()
    payload["approved_scope_rules"] = ["other.example"]
    with pytest.raises(ValidationError, match="not covered"):
        WorkerTaskEnvelope.model_validate(payload)


def test_worker_envelope_rejects_malformed_or_duplicate_scope_rules():
    payload = valid_payload()
    payload["approved_scope_rules"] = ["*.com"]
    with pytest.raises(ValidationError):
        WorkerTaskEnvelope.model_validate(payload)
    payload["approved_scope_rules"] = ["example.org", "example.org"]
    with pytest.raises(ValidationError, match="duplicate"):
        WorkerTaskEnvelope.model_validate(payload)
