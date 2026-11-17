import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core import worker_transport
from app.core.worker_protocol import WorkerTaskEnvelope
from app.core.worker_signing import verify_worker_task

WORKER_ID = "local-validator"
KEY_ID = "local-validator-v1"


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


def test_issue_signed_task_revalidates_reserves_and_signs(monkeypatch):
    private, public = _keypair()
    now = datetime.now(timezone.utc)
    envelope = WorkerTaskEnvelope(
        task_id=uuid4(), job_id=22, scope_snapshot_id=33,
        scope_snapshot_sha256="c" * 64, profile="passive_recon",
        target_url="https://example.net/", issued_at=now,
        expires_at=now + timedelta(minutes=1), execution_enabled=False,
    )
    events = []
    monkeypatch.setattr(worker_transport, "prepare_dispatch_envelope",
        lambda db, job_id, **kwargs: events.append(("revalidate", job_id)) or envelope)
    monkeypatch.setattr(worker_transport, "reserve_task_receipt",
        lambda db, task, **kwargs: events.append(("reserve", task.task_id)))
    signed = worker_transport.issue_signed_worker_task(
        object(), 22, backend_private_key_b64=private,
        worker_id=WORKER_ID, key_id=KEY_ID, now=now
    )
    assert events == [("revalidate", 22), ("reserve", envelope.task_id)]
    assert verify_worker_task(
        signed, public, expected_worker_id=WORKER_ID, expected_key_id=KEY_ID
    )


def test_invalid_signing_key_does_not_reserve_job(monkeypatch):
    now = datetime.now(timezone.utc)
    envelope = WorkerTaskEnvelope(
        task_id=uuid4(), job_id=23, scope_snapshot_id=34,
        scope_snapshot_sha256="d" * 64, profile="passive_recon",
        target_url="https://example.net/", issued_at=now,
        expires_at=now + timedelta(minutes=1), execution_enabled=False,
    )
    reserved = []
    monkeypatch.setattr(worker_transport, "prepare_dispatch_envelope", lambda *a, **k: envelope)
    monkeypatch.setattr(worker_transport, "reserve_task_receipt", lambda *a, **k: reserved.append(True))
    import pytest
    with pytest.raises(ValueError, match="invalid Ed25519 private key"):
        worker_transport.issue_signed_worker_task(
            object(), 23, backend_private_key_b64="invalid",
            worker_id=WORKER_ID, key_id=KEY_ID, now=now
        )
    assert reserved == []
