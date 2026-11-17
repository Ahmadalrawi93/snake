from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.worker_protocol import WorkerTaskEnvelope, WorkerValidationResult
from app.core.worker_signing import (\n    sign_worker_task, verify_worker_task,\n    sign_worker_validation_result, verify_worker_validation_result,\n)


SECRET = "test-worker-signing-secret-at-least-32-chars"


def _task():
    now = datetime.now(timezone.utc)
    return WorkerTaskEnvelope(
        task_id=uuid4(),
        job_id=8,
        scope_snapshot_id=9,
        scope_snapshot_sha256="c" * 64,
        profile="passive_recon",
        target_url="https://example.com/",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        execution_enabled=False,
    )


def test_signed_task_round_trip():
    signed = sign_worker_task(_task(), SECRET)
    assert verify_worker_task(signed, SECRET)


def test_signature_rejects_tampered_envelope():
    signed = sign_worker_task(_task(), SECRET)
    tampered = signed.model_copy(update={
        "envelope": signed.envelope.model_copy(update={"job_id": 99})
    })
    assert not verify_worker_task(tampered, SECRET)


def test_signature_rejects_wrong_secret():
    signed = sign_worker_task(_task(), SECRET)
    assert not verify_worker_task(signed, "another-worker-secret-at-least-32-chars")


@pytest.mark.parametrize("secret", ["", "short"])
def test_signing_rejects_weak_secret(secret):
    with pytest.raises(ValueError):
        sign_worker_task(_task(), secret)


def _validation_result():
    return WorkerValidationResult(
        task_id=uuid4(),
        envelope_sha256="d" * 64,
        worker_id="validator-01",
        outcome="accepted",
        validated_at=datetime.now(timezone.utc),
        execution_enabled=False,
    )


def test_worker_validation_result_signature_round_trip():
    signed = sign_worker_validation_result(_validation_result(), SECRET)
    assert verify_worker_validation_result(signed, SECRET)


def test_worker_validation_result_signature_rejects_tampering():
    signed = sign_worker_validation_result(_validation_result(), SECRET)
    tampered = signed.model_copy(update={
        "result": signed.result.model_copy(update={"worker_id": "forged-worker"})
    })
    assert not verify_worker_validation_result(tampered, SECRET)


def test_worker_validation_result_cannot_claim_execution():
    with pytest.raises(Exception):
        WorkerValidationResult(
            task_id=uuid4(),
            envelope_sha256="d" * 64,
            worker_id="validator-01",
            outcome="accepted",
            validated_at=datetime.now(timezone.utc),
            execution_enabled=True,
        )
