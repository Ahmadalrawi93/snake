import base64
import io
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.worker_protocol import WorkerTaskEnvelope
from app.core.worker_signing import (
    SignedWorkerValidationResult, sign_worker_task, verify_worker_validation_result,
)
from worker_entrypoint import main

WORKER_ID = "test-validator"
KEY_ID = "test-validator-v1"


def _keypair():
    key = Ed25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )).decode()
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    return private, public


BACKEND_PRIVATE, BACKEND_PUBLIC = _keypair()
WORKER_PRIVATE, WORKER_PUBLIC = _keypair()
OTHER_PRIVATE, _ = _keypair()


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
    monkeypatch.setenv("SNAKE_BACKEND_ED25519_PUBLIC_KEY_B64", BACKEND_PUBLIC)
    monkeypatch.setenv("SNAKE_WORKER_ED25519_PRIVATE_KEY_B64", WORKER_PRIVATE)
    monkeypatch.setenv("SNAKE_WORKER_ID", WORKER_ID)
    monkeypatch.setenv("SNAKE_WORKER_KEY_ID", KEY_ID)


def test_worker_verifies_backend_task_and_signs_ack(monkeypatch, capsys):
    _configure(monkeypatch)
    task = sign_worker_task(_task(), BACKEND_PRIVATE, worker_id=WORKER_ID, key_id=KEY_ID)
    assert _run(monkeypatch, task.model_dump_json()) == 0
    result = SignedWorkerValidationResult.model_validate_json(capsys.readouterr().out)
    assert result.result.outcome == "accepted"
    assert result.result.execution_enabled is False
    assert result.result.worker_id == WORKER_ID
    assert result.key_id == KEY_ID
    assert verify_worker_validation_result(
        result, WORKER_PUBLIC, expected_worker_id=WORKER_ID, expected_key_id=KEY_ID
    )


def test_worker_rejects_tampered_task(monkeypatch, capsys):
    _configure(monkeypatch)
    task = sign_worker_task(_task(), BACKEND_PRIVATE, worker_id=WORKER_ID, key_id=KEY_ID)
    payload = json.loads(task.model_dump_json())
    payload["envelope"]["job_id"] = 99
    assert _run(monkeypatch, json.dumps(payload)) == 2
    assert "signature" in capsys.readouterr().err


def test_worker_rejects_task_signed_by_non_backend_key(monkeypatch, capsys):
    _configure(monkeypatch)
    task = sign_worker_task(_task(), OTHER_PRIVATE, worker_id=WORKER_ID, key_id=KEY_ID)
    assert _run(monkeypatch, task.model_dump_json()) == 2
    assert "signature" in capsys.readouterr().err


def test_worker_rejects_task_for_another_identity(monkeypatch, capsys):
    _configure(monkeypatch)
    task = sign_worker_task(_task(), BACKEND_PRIVATE, worker_id="other-worker", key_id=KEY_ID)
    assert _run(monkeypatch, task.model_dump_json()) == 2
    assert "worker binding" in capsys.readouterr().err


def test_worker_requires_all_asymmetric_key_material(monkeypatch, capsys):
    for name in (
        "SNAKE_BACKEND_ED25519_PUBLIC_KEY_B64",
        "SNAKE_WORKER_ED25519_PRIVATE_KEY_B64",
        "SNAKE_WORKER_ID", "SNAKE_WORKER_KEY_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    assert _run(monkeypatch, "{}") == 2
    assert "Backend public key" in capsys.readouterr().err


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
    signed = sign_worker_task(task, BACKEND_PRIVATE, worker_id=WORKER_ID, key_id=KEY_ID)
    assert _run(monkeypatch, signed.model_dump_json()) == 2
    assert "expired" in capsys.readouterr().err


def test_worker_rejects_oversized_input(monkeypatch, capsys):
    assert _run(monkeypatch, "x" * (64 * 1024 + 1)) == 2
    assert "64 KiB" in capsys.readouterr().err
