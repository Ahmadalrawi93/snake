import io
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.core.worker_protocol import WorkerTaskEnvelope
from app.core.worker_signing import (
    SignedWorkerValidationResult, sign_worker_task, verify_worker_validation_result,
)
from worker_entrypoint import main

SECRET = "validator-secret-for-tests-at-least-32-characters"
WORKER_ID = "test-validator"
KEY_ID = "test-validator-v1"


def _task():
    now = datetime.now(timezone.utc)
    return WorkerTaskEnvelope(
        task_id=uuid4(), job_id=1, scope_snapshot_id=2,
        scope_snapshot_sha256="a" * 64, profile="passive_recon",
        target_url="https://example.com/", issued_at=now,
        expires_at=now + timedelta(minutes=2), execution_enabled=False,
    )


def _run(monkeypatch, payload):
    raw = payload.encode()
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(raw)))
    return main()


def _configure(monkeypatch):
    monkeypatch.setenv("SNAKE_WORKER_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("SNAKE_WORKER_ID", WORKER_ID)
    monkeypatch.setenv("SNAKE_WORKER_KEY_ID", KEY_ID)


def test_worker_verifies_signed_task_and_returns_signed_ack(monkeypatch, capsys):
    _configure(monkeypatch)
    signed_task = sign_worker_task(_task(), SECRET, worker_id=WORKER_ID, key_id=KEY_ID)
    assert _run(monkeypatch, signed_task.model_dump_json()) == 0
    result = SignedWorkerValidationResult.model_validate_json(capsys.readouterr().out)
    assert result.result.outcome == "accepted"
    assert result.result.execution_enabled is False
    assert result.result.worker_id == WORKER_ID
    assert result.key_id == KEY_ID
    assert verify_worker_validation_result(result, SECRET, expected_key_id=KEY_ID)


def test_worker_rejects_unsigned_or_tampered_task(monkeypatch, capsys):
    _configure(monkeypatch)
    signed_task = sign_worker_task(_task(), SECRET, worker_id=WORKER_ID, key_id=KEY_ID)
    payload = json.loads(signed_task.model_dump_json())
    payload["envelope"]["job_id"] = 99
    assert _run(monkeypatch, json.dumps(payload)) == 2
    assert "signature" in capsys.readouterr().err


def test_worker_rejects_task_for_another_identity(monkeypatch, capsys):
    _configure(monkeypatch)
    signed_task = sign_worker_task(_task(), SECRET, worker_id="other-worker", key_id=KEY_ID)
    assert _run(monkeypatch, signed_task.model_dump_json()) == 2
    assert "worker binding" in capsys.readouterr().err


def test_worker_requires_unique_identity_configuration(monkeypatch, capsys):
    monkeypatch.delenv("SNAKE_WORKER_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("SNAKE_WORKER_ID", raising=False)
    monkeypatch.delenv("SNAKE_WORKER_KEY_ID", raising=False)
    assert _run(monkeypatch, "{}") == 2
    assert "Unique worker secret" in capsys.readouterr().err


def test_worker_rejects_command_fields(monkeypatch, capsys):
    _configure(monkeypatch)
    payload = _task().model_dump(mode="json")
    payload["command"] = "id"
    assert _run(monkeypatch, json.dumps(payload)) == 2
    assert "signature" in capsys.readouterr().err.lower()


def test_worker_rejects_expired_signed_task(monkeypatch, capsys):
    _configure(monkeypatch)
    task = _task().model_copy(update={
        "issued_at": datetime.now(timezone.utc) - timedelta(minutes=5),
        "expires_at": datetime.now(timezone.utc) - timedelta(minutes=1),
    })
    signed_task = sign_worker_task(task, SECRET, worker_id=WORKER_ID, key_id=KEY_ID)
    assert _run(monkeypatch, signed_task.model_dump_json()) == 2
    assert "expired" in capsys.readouterr().err


def test_worker_rejects_oversized_input(monkeypatch, capsys):
    assert _run(monkeypatch, "x" * (64 * 1024 + 1)) == 2
    assert "64 KiB" in capsys.readouterr().err
