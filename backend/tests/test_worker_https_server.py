import base64
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.worker_protocol import WorkerTaskEnvelope
from app.core.worker_signing import (
    SignedWorkerValidationResult,
    sign_worker_task,
    verify_worker_validation_result,
)
from worker_https_server import MAX_BODY_BYTES, validate_task_request


def keypair():
    key = Ed25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )).decode()
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    return private, public


def make_task():
    now = datetime.now(timezone.utc)
    return WorkerTaskEnvelope(
        task_id=uuid4(), job_id=10, scope_snapshot_id=20,
        scope_snapshot_sha256="a" * 64, profile="passive_recon",
        target_url="https://example.com/", issued_at=now,
        expires_at=now + timedelta(minutes=2), execution_enabled=False,
    )


def test_https_worker_returns_signed_validation_ack():
    backend_private, backend_public = keypair()
    worker_private, worker_public = keypair()
    task = sign_worker_task(
        make_task(), backend_private, worker_id="worker-1", key_id="key-1"
    )
    response = validate_task_request(
        task.model_dump_json().encode(),
        backend_public_key=backend_public,
        worker_private_key=worker_private,
        worker_id="worker-1",
        key_id="key-1",
    )
    ack = SignedWorkerValidationResult.model_validate_json(response)
    assert ack.result.outcome == "accepted"
    assert ack.result.execution_enabled is False
    assert verify_worker_validation_result(
        ack, worker_public, expected_worker_id="worker-1", expected_key_id="key-1"
    )


def test_https_worker_rejects_tampered_task():
    backend_private, backend_public = keypair()
    worker_private, _ = keypair()
    task = sign_worker_task(
        make_task(), backend_private, worker_id="worker-1", key_id="key-1"
    )
    payload = json.loads(task.model_dump_json())
    payload["envelope"]["job_id"] = 999
    with pytest.raises(ValueError, match="signature"):
        validate_task_request(
            json.dumps(payload).encode(),
            backend_public_key=backend_public,
            worker_private_key=worker_private,
            worker_id="worker-1",
            key_id="key-1",
        )


def test_https_worker_rejects_wrong_worker_identity():
    backend_private, backend_public = keypair()
    worker_private, _ = keypair()
    task = sign_worker_task(
        make_task(), backend_private, worker_id="other", key_id="key-1"
    )
    with pytest.raises(ValueError, match="signature"):
        validate_task_request(
            task.model_dump_json().encode(),
            backend_public_key=backend_public,
            worker_private_key=worker_private,
            worker_id="worker-1",
            key_id="key-1",
        )


def test_https_worker_rejects_oversized_body():
    _, backend_public = keypair()
    worker_private, _ = keypair()
    with pytest.raises(ValueError, match="body size"):
        validate_task_request(
            b"x" * (MAX_BODY_BYTES + 1),
            backend_public_key=backend_public,
            worker_private_key=worker_private,
            worker_id="worker-1",
            key_id="key-1",
        )
