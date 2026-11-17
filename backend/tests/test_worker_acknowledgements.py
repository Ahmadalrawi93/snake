from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.worker_acknowledgements import accept_worker_acknowledgement
from app.core.worker_protocol import WorkerValidationResult
from app.core.worker_signing import sign_worker_validation_result
from app.db.models import WorkerTaskReceipt

SECRET = "worker-ack-test-secret-with-more-than-32-characters"
WORKER_ID = "validator-east-01"


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    WorkerTaskReceipt.__table__.create(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def make_receipt(db):
    now = datetime.now(timezone.utc)
    task_id = uuid4()
    receipt = WorkerTaskReceipt(
        task_id=str(task_id),
        job_id=100,
        envelope_sha256="a" * 64,
        expires_at=now + timedelta(minutes=2),
        consumed_at=None,
        created_at=now - timedelta(seconds=1),
    )
    db.add(receipt)
    db.commit()
    return receipt, task_id


def make_ack(task_id, *, digest="a" * 64, worker_id=WORKER_ID, outcome="accepted"):
    result = WorkerValidationResult(
        task_id=task_id,
        envelope_sha256=digest,
        worker_id=worker_id,
        outcome=outcome,
        validated_at=datetime.now(timezone.utc),
        execution_enabled=False,
    )
    return sign_worker_validation_result(result, SECRET)


def test_valid_ack_is_bound_and_consumed_once(db):
    receipt, task_id = make_receipt(db)
    signed = make_ack(task_id)
    assert accept_worker_acknowledgement(
        db, signed, secret=SECRET, expected_worker_id=WORKER_ID
    )
    db.refresh(receipt)
    assert receipt.consumed_at is not None
    assert receipt.acknowledgement_outcome == "accepted"
    assert receipt.acknowledgement_worker_id == WORKER_ID
    assert not accept_worker_acknowledgement(
        db, signed, secret=SECRET, expected_worker_id=WORKER_ID
    )


def test_ack_rejects_wrong_worker_identity(db):
    _, task_id = make_receipt(db)
    signed = make_ack(task_id)
    assert not accept_worker_acknowledgement(
        db, signed, secret=SECRET, expected_worker_id="different-worker"
    )


def test_ack_rejects_digest_mismatch(db):
    _, task_id = make_receipt(db)
    signed = make_ack(task_id, digest="b" * 64)
    assert not accept_worker_acknowledgement(
        db, signed, secret=SECRET, expected_worker_id=WORKER_ID
    )


def test_ack_rejects_tampered_signature(db):
    _, task_id = make_receipt(db)
    signed = make_ack(task_id)
    tampered = signed.model_copy(update={
        "result": signed.result.model_copy(update={"outcome": "rejected"})
    })
    assert not accept_worker_acknowledgement(
        db, tampered, secret=SECRET, expected_worker_id=WORKER_ID
    )


def test_ack_rejects_expired_receipt(db):
    receipt, task_id = make_receipt(db)
    receipt.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    signed = make_ack(task_id)
    assert not accept_worker_acknowledgement(
        db, signed, secret=SECRET, expected_worker_id=WORKER_ID
    )


def test_ack_rejects_unknown_task(db):
    signed = make_ack(uuid4())
    assert not accept_worker_acknowledgement(
        db, signed, secret=SECRET, expected_worker_id=WORKER_ID
    )
