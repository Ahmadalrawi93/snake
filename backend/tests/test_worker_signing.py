from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.worker_protocol import WorkerTaskEnvelope, WorkerValidationResult
from app.core.worker_signing import (
    sign_worker_task, verify_worker_task,
    sign_worker_validation_result, verify_worker_validation_result,
)

SECRET = "test-worker-signing-secret-at-least-32-chars"
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


def _verify(signed, secret=SECRET, worker=WORKER_ID, key=KEY_ID):
    return verify_worker_task(
        signed, secret, expected_worker_id=worker, expected_key_id=key
    )


def test_signed_task_round_trip():
    signed = sign_worker_task(_task(), SECRET, worker_id=WORKER_ID, key_id=KEY_ID)
    assert _verify(signed)


def test_signature_rejects_tampered_envelope():
    signed = sign_worker_task(_task(), SECRET, worker_id=WORKER_ID, key_id=KEY_ID)
    tampered = signed.model_copy(update={
        "envelope": signed.envelope.model_copy(update={"job_id": 99})
    })
    assert not _verify(tampered)


def test_signature_rejects_wrong_secret():
    signed = sign_worker_task(_task(), SECRET, worker_id=WORKER_ID, key_id=KEY_ID)
    assert not _verify(signed, "another-worker-secret-at-least-32-chars")


def test_task_is_bound_to_worker_and_key_id():
    signed = sign_worker_task(_task(), SECRET, worker_id=WORKER_ID, key_id=KEY_ID)
    assert not _verify(signed, worker="different-worker")
    assert not _verify(signed, key="retired-key")


@pytest.mark.parametrize("secret", ["", "short"])
def test_signing_rejects_weak_secret(secret):
    with pytest.raises(ValueError):
        sign_worker_task(_task(), secret, worker_id=WORKER_ID, key_id=KEY_ID)


def _validation_result():
    return WorkerValidationResult(
        task_id=uuid4(), envelope_sha256="d" * 64, worker_id=WORKER_ID,
        outcome="accepted", validated_at=datetime.now(timezone.utc),
        execution_enabled=False,
    )


def test_worker_validation_result_signature_round_trip():
    signed = sign_worker_validation_result(_validation_result(), SECRET, key_id=KEY_ID)
    assert verify_worker_validation_result(signed, SECRET, expected_key_id=KEY_ID)


def test_worker_validation_result_signature_rejects_tampering():
    signed = sign_worker_validation_result(_validation_result(), SECRET, key_id=KEY_ID)
    tampered = signed.model_copy(update={
        "result": signed.result.model_copy(update={"worker_id": "forged-worker"})
    })
    assert not verify_worker_validation_result(tampered, SECRET, expected_key_id=KEY_ID)


def test_result_rejects_unknown_key_id():
    signed = sign_worker_validation_result(_validation_result(), SECRET, key_id=KEY_ID)
    assert not verify_worker_validation_result(signed, SECRET, expected_key_id="unknown-v9")


def test_worker_validation_result_cannot_claim_execution():
    with pytest.raises(Exception):
        WorkerValidationResult(
            task_id=uuid4(), envelope_sha256="d" * 64, worker_id=WORKER_ID,
            outcome="accepted", validated_at=datetime.now(timezone.utc),
            execution_enabled=True,
        )
