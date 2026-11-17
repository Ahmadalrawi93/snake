import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.worker_protocol import WorkerTaskEnvelope, WorkerValidationResult
from app.core.worker_signing import (
    sign_worker_task, verify_worker_task,
    sign_worker_validation_result, verify_worker_validation_result,
)


def keypair():
    key = Ed25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )).decode()
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    return private, public


BACKEND_PRIVATE, BACKEND_PUBLIC = keypair()
WORKER_PRIVATE, WORKER_PUBLIC = keypair()
WORKER_ID = "validator-01"
KEY_ID = "validator-01-v1"


def _task():
    now = datetime.now(timezone.utc)
    return WorkerTaskEnvelope(
        task_id=uuid4(), job_id=8, scope_snapshot_id=9,
        scope_snapshot_sha256="c" * 64, profile="passive_recon",
        target_url="https://example.com/", issued_at=now,
        expires_at=now + timedelta(minutes=2), execution_enabled=False,
    )


def test_backend_signs_task_worker_verifies_with_public_key():
    signed = sign_worker_task(_task(), BACKEND_PRIVATE, worker_id=WORKER_ID, key_id=KEY_ID)
    assert verify_worker_task(
        signed, BACKEND_PUBLIC, expected_worker_id=WORKER_ID, expected_key_id=KEY_ID
    )


def test_worker_cannot_sign_backend_task_with_its_private_key():
    signed = sign_worker_task(_task(), BACKEND_PRIVATE, worker_id=WORKER_ID, key_id=KEY_ID)
    assert not verify_worker_task(
        signed, WORKER_PUBLIC, expected_worker_id=WORKER_ID, expected_key_id=KEY_ID
    )


def test_task_signature_rejects_tampering_and_wrong_binding():
    signed = sign_worker_task(_task(), BACKEND_PRIVATE, worker_id=WORKER_ID, key_id=KEY_ID)
    tampered = signed.model_copy(update={
        "envelope": signed.envelope.model_copy(update={"job_id": 99})
    })
    assert not verify_worker_task(
        tampered, BACKEND_PUBLIC, expected_worker_id=WORKER_ID, expected_key_id=KEY_ID
    )
    assert not verify_worker_task(
        signed, BACKEND_PUBLIC, expected_worker_id="other-worker", expected_key_id=KEY_ID
    )
    assert not verify_worker_task(
        signed, BACKEND_PUBLIC, expected_worker_id=WORKER_ID, expected_key_id="retired-v0"
    )


def _result():
    return WorkerValidationResult(
        task_id=uuid4(), envelope_sha256="d" * 64, worker_id=WORKER_ID,
        outcome="accepted", validated_at=datetime.now(timezone.utc),
        execution_enabled=False,
    )


def test_worker_signs_ack_backend_verifies_public_key():
    signed = sign_worker_validation_result(_result(), WORKER_PRIVATE, key_id=KEY_ID)
    assert verify_worker_validation_result(
        signed, WORKER_PUBLIC, expected_worker_id=WORKER_ID, expected_key_id=KEY_ID
    )


def test_backend_cannot_forge_worker_ack():
    signed = sign_worker_validation_result(_result(), BACKEND_PRIVATE, key_id=KEY_ID)
    assert not verify_worker_validation_result(
        signed, WORKER_PUBLIC, expected_worker_id=WORKER_ID, expected_key_id=KEY_ID
    )


def test_ack_rejects_tampering_wrong_worker_and_unknown_key():
    signed = sign_worker_validation_result(_result(), WORKER_PRIVATE, key_id=KEY_ID)
    tampered = signed.model_copy(update={
        "result": signed.result.model_copy(update={"outcome": "rejected"})
    })
    assert not verify_worker_validation_result(
        tampered, WORKER_PUBLIC, expected_worker_id=WORKER_ID, expected_key_id=KEY_ID
    )
    assert not verify_worker_validation_result(
        signed, WORKER_PUBLIC, expected_worker_id="other-worker", expected_key_id=KEY_ID
    )
    assert not verify_worker_validation_result(
        signed, WORKER_PUBLIC, expected_worker_id=WORKER_ID, expected_key_id="unknown-v2"
    )


def test_non_ed25519_key_is_rejected():
    with pytest.raises(ValueError):
        sign_worker_task(_task(), "not-base64", worker_id=WORKER_ID, key_id=KEY_ID)


def test_validation_result_cannot_claim_execution():
    with pytest.raises(Exception):
        WorkerValidationResult(
            task_id=uuid4(), envelope_sha256="d" * 64, worker_id=WORKER_ID,
            outcome="accepted", validated_at=datetime.now(timezone.utc),
            execution_enabled=True,
        )
