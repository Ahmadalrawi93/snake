import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.worker_acknowledgements import (
    accept_worker_acknowledgement, reconcile_unknown_worker_acknowledgement,
)
from app.core.worker_key_registry import revoke_worker_public_key
from app.core.worker_protocol import WorkerValidationResult
from app.core.worker_signing import ed25519_public_key_fingerprint, sign_worker_validation_result
from app.db.models import WorkerDispatchAttempt, WorkerKey, WorkerTaskReceipt

WORKER_ID = "validator-east-01"
KEY_ID = "validator-east-01-v1"


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


WORKER_PRIVATE, WORKER_PUBLIC = keypair()
OTHER_PRIVATE, _ = keypair()


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    WorkerTaskReceipt.__table__.create(engine)
    WorkerKey.__table__.create(engine)
    WorkerDispatchAttempt.__table__.create(engine)
    with Session(engine) as session:
        session.add(WorkerKey(
            worker_id=WORKER_ID, key_id=KEY_ID,
            public_key_b64=WORKER_PUBLIC,
            fingerprint_sha256=ed25519_public_key_fingerprint(WORKER_PUBLIC),
            status="active", created_by=None,
        ))
        session.commit()
        yield session
    engine.dispose()


def make_receipt(db):
    now = datetime.now(timezone.utc)
    task_id = uuid4()
    receipt = WorkerTaskReceipt(
        task_id=str(task_id), job_id=100, envelope_sha256="a" * 64,
        worker_id=WORKER_ID, key_id=KEY_ID,
        expires_at=now + timedelta(minutes=2), consumed_at=None,
        created_at=now - timedelta(seconds=1),
    )
    db.add(receipt)
    db.commit()
    return receipt, task_id


def make_ack(task_id, *, digest="a" * 64, worker_id=WORKER_ID, key_id=KEY_ID, private=WORKER_PRIVATE, validated_at=None):
    result = WorkerValidationResult(
        task_id=task_id, envelope_sha256=digest, worker_id=worker_id,
        outcome="accepted", validated_at=validated_at or datetime.now(timezone.utc),
        execution_enabled=False,
    )
    return sign_worker_validation_result(result, private, key_id=key_id)


def accept(db, signed, **kwargs):
    return accept_worker_acknowledgement(
        db, signed, expected_worker_id=WORKER_ID,
        expected_key_id=KEY_ID, **kwargs
    )


def test_valid_ack_is_bound_and_consumed_once(db):
    receipt, task_id = make_receipt(db)
    signed = make_ack(task_id)
    assert accept(db, signed)
    db.refresh(receipt)
    assert receipt.consumed_at is not None
    assert receipt.acknowledgement_outcome == "accepted"
    assert receipt.acknowledgement_worker_id == WORKER_ID
    assert not accept(db, signed)


def test_ack_rejects_wrong_worker_identity(db):
    _, task_id = make_receipt(db)
    assert not accept(db, make_ack(task_id, worker_id="different-worker"))


def test_ack_rejects_unknown_key_id(db):
    _, task_id = make_receipt(db)
    assert not accept(db, make_ack(task_id, key_id="unknown-key-v9"))


def test_ack_rejects_digest_mismatch(db):
    _, task_id = make_receipt(db)
    assert not accept(db, make_ack(task_id, digest="b" * 64))


def test_ack_rejects_signature_from_another_private_key(db):
    _, task_id = make_receipt(db)
    assert not accept(db, make_ack(task_id, private=OTHER_PRIVATE))


def test_ack_rejects_tampered_signature(db):
    _, task_id = make_receipt(db)
    signed = make_ack(task_id)
    tampered = signed.model_copy(update={
        "result": signed.result.model_copy(update={"outcome": "rejected"})
    })
    assert not accept(db, tampered)


def test_revoked_worker_key_cannot_acknowledge(db):
    _, task_id = make_receipt(db)
    revoke_worker_public_key(db, worker_id=WORKER_ID, key_id=KEY_ID)
    db.commit()
    assert not accept(db, make_ack(task_id))


def test_ack_rejects_expired_receipt(db):
    receipt, task_id = make_receipt(db)
    receipt.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert not accept(db, make_ack(task_id))


def test_ack_rejects_unknown_task(db):
    assert not accept(db, make_ack(uuid4()))


def test_ack_rejects_receipt_bound_to_different_worker_key(db):
    receipt, task_id = make_receipt(db)
    receipt.worker_id = "different-worker"
    db.commit()
    assert not accept(db, make_ack(task_id))



def make_unknown_attempt(db, receipt):
    attempt = WorkerDispatchAttempt(
        task_id=receipt.task_id,
        attempt_number=1,
        worker_id=receipt.worker_id,
        key_id=receipt.key_id,
        envelope_sha256=receipt.envelope_sha256,
        status="unknown",
        error_code="transport_exception",
        started_at=receipt.created_at,
        completed_at=receipt.created_at + timedelta(seconds=5),
    )
    db.add(attempt)
    db.commit()
    return attempt


def test_reconcile_late_signed_ack_after_receipt_expiry(db):
    receipt, task_id = make_receipt(db)
    attempt = make_unknown_attempt(db, receipt)
    created_at = receipt.created_at.replace(tzinfo=timezone.utc) if receipt.created_at.tzinfo is None else receipt.created_at
    expires_at = receipt.expires_at.replace(tzinfo=timezone.utc) if receipt.expires_at.tzinfo is None else receipt.expires_at
    validated_at = created_at + timedelta(seconds=20)
    signed = make_ack(task_id, validated_at=validated_at)
    reconciliation_time = expires_at + timedelta(minutes=1)

    assert reconcile_unknown_worker_acknowledgement(
        db, signed, expected_worker_id=WORKER_ID,
        expected_key_id=KEY_ID, now=reconciliation_time,
    )
    db.commit()
    db.refresh(receipt)
    db.refresh(attempt)
    assert receipt.consumed_at == reconciliation_time
    assert receipt.acknowledgement_validated_at == validated_at
    assert attempt.status == "delivered"
    assert attempt.error_code is None
    assert not reconcile_unknown_worker_acknowledgement(
        db, signed, expected_worker_id=WORKER_ID,
        expected_key_id=KEY_ID, now=reconciliation_time,
    )


def test_reconciliation_rejects_ack_validated_after_original_expiry(db):
    receipt, task_id = make_receipt(db)
    make_unknown_attempt(db, receipt)
    signed = make_ack(
        task_id, validated_at=(receipt.expires_at.replace(tzinfo=timezone.utc) if receipt.expires_at.tzinfo is None else receipt.expires_at) + timedelta(seconds=1)
    )
    assert not reconcile_unknown_worker_acknowledgement(
        db, signed, expected_worker_id=WORKER_ID,
        expected_key_id=KEY_ID, now=(receipt.expires_at.replace(tzinfo=timezone.utc) if receipt.expires_at.tzinfo is None else receipt.expires_at) + timedelta(minutes=1),
    )


def test_reconciliation_requires_unknown_attempt_and_active_key(db):
    receipt, task_id = make_receipt(db)
    attempt = make_unknown_attempt(db, receipt)
    attempt.status = "failed"
    db.commit()
    signed = make_ack(task_id)
    assert not reconcile_unknown_worker_acknowledgement(
        db, signed, expected_worker_id=WORKER_ID,
        expected_key_id=KEY_ID,
    )
    attempt.status = "unknown"
    revoke_worker_public_key(db, worker_id=WORKER_ID, key_id=KEY_ID)
    db.commit()
    assert not reconcile_unknown_worker_acknowledgement(
        db, signed, expected_worker_id=WORKER_ID,
        expected_key_id=KEY_ID,
    )
