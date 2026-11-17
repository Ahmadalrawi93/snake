from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.worker_protocol import WorkerTaskEnvelope
from app.core.worker_signing import sign_worker_task, verify_worker_task


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
