import io
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.core.worker_protocol import WorkerTaskEnvelope
from app.core.worker_signing import (
    SignedWorkerValidationResult,
    sign_worker_task,
    verify_worker_validation_result,
)
from worker_entrypoint import main

SECRET = "validator-secret-for-tests-at-least-32-characters"


def _task():
    now = datetime.now(timezone.utc)
    return WorkerTaskEnvelope(
        task_id=uuid4(),
        job_id=1,
        scope_snapshot_id=2,
        scope_snapshot_sha256="a" * 64,
        profile="passive_recon",
        target_url="https://example.com/",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        execution_enabled=False,
    )


def _run(monkeypatch, payload):
    raw = payload.encode()
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(raw)))
    return main()


def test_worker_verifies_signed_task_and_returns_signed_ack(monkeypatch, capsys):
    monkeypatch.setenv("SNAKE_WORKER_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("SNAKE_WORKER_ID", "test-validator")
    signed_task = sign_worker_task(_task(), SECRET)
    assert _run(monkeypatch, signed_task.model_dump_json()) == 0

    result = SignedWorkerValidationResult.model_validate_json(capsys.readouterr().out)
    assert result.result.outcome == "accepted"
    assert result.result.execution_enabled is False
    assert result.result.worker_id == "test-validator"
    assert verify_worker_validation_result(result, SECRET)


def test_worker_rejects_unsigned_or_tampered_task(monkeypatch, capsys):
    monkeypatch.setenv("SNAKE_WORKER_SIGNING_SECRET", SECRET)
    signed_task = sign_worker_task(_task(), SECRET)
    payload = json.loads(signed_task.model_dump_json())
    payload["envelope"]["job_id"] = 99
    assert _run(monkeypatch, json.dumps(payload)) == 2
    assert "signature verification failed" in capsys.readouterr().err


def test_worker_requires_dedicated_secret(monkeypatch, capsys):
    monkeypatch.delenv("SNAKE_WORKER_SIGNING_SECRET", raising=False)
    assert _run(monkeypatch, "{}") == 2
    assert "secret is not configured" in capsys.readouterr().err


def test_worker_rejects_command_fields(monkeypatch, capsys):
    monkeypatch.setenv("SNAKE_WORKER_SIGNING_SECRET", SECRET)
    payload = _task().model_dump(mode="json")
    payload["command"] = "id"
    assert _run(monkeypatch, json.dumps(payload)) == 2
    assert "signature" in capsys.readouterr().err.lower()
