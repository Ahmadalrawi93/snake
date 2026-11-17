from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.worker_protocol import WorkerTaskEnvelope, ensure_not_expired


def valid_payload():
    now = datetime.now(timezone.utc)
    return {
        "task_id": str(uuid4()),
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
