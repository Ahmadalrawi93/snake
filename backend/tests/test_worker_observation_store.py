import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.worker_key_registry import revoke_worker_public_key
from app.core.worker_observation_signing import sign_worker_observation_batch
from app.core.worker_observation_store import store_worker_observation_batch
from app.db.models import WorkerKey, WorkerObservationRecord, WorkerTaskReceipt
from app.core.worker_signing import ed25519_public_key_fingerprint
from app.schemas.worker_results import WorkerObservation, WorkerObservationBatch

WORKER_ID = "recon-worker-01"
KEY_ID = "recon-key-v1"


def make_keypair():
    key = Ed25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )).decode()
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    return private, public


PRIVATE, PUBLIC = make_keypair()
OTHER_PRIVATE, _ = make_keypair()


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    WorkerTaskReceipt.__table__.create(engine)
    WorkerKey.__table__.create(engine)
    WorkerObservationRecord.__table__.create(engine)
    with Session(engine) as session:
        session.add(WorkerKey(
            worker_id=WORKER_ID, key_id=KEY_ID, public_key_b64=PUBLIC,
            fingerprint_sha256=ed25519_public_key_fingerprint(PUBLIC),
            status="active", created_by=None,
        ))
        session.add(WorkerTaskReceipt(
            task_id=str(TASK_ID), job_id=901, envelope_sha256="c" * 64,
            worker_id=WORKER_ID, key_id=KEY_ID,
            expires_at=NOW + timedelta(minutes=3),
            consumed_at=NOW, acknowledgement_outcome="accepted",
            acknowledgement_worker_id=WORKER_ID, created_at=NOW - timedelta(seconds=30),
        ))
        session.commit()
        yield session
    engine.dispose()


NOW = datetime.now(timezone.utc)
TASK_ID = uuid4()


def make_batch(**overrides):
    data = dict(
        task_id=TASK_ID,
        envelope_sha256="c" * 64,
        worker_id=WORKER_ID,
        key_id=KEY_ID,
        collected_at=NOW,
        observations=[WorkerObservation(
            observation_id=uuid4(),
            kind="hostname",
            value="api.example.test",
            evidence="Observed in passive DNS dataset",
            source="passive_dns",
            observed_at=NOW - timedelta(seconds=2),
        )],
        execution_enabled=False,
    )
    data.update(overrides)
    return WorkerObservationBatch(**data)


def test_valid_signed_batch_persists_only_unconfirmed_observation(db):
    signed = sign_worker_observation_batch(make_batch(), PRIVATE)
    assert store_worker_observation_batch(db, signed, now=NOW) == 1
    record = db.scalar(select(WorkerObservationRecord))
    assert record.value == "api.example.test"
    assert record.classification == "unconfirmed_observation"
    assert record.batch_sha256
    assert record.batch_signature == signed.signature
    assert record.batch_payload_json
    assert record.worker_id == WORKER_ID


def test_invalid_signature_is_rejected(db):
    signed = sign_worker_observation_batch(make_batch(), OTHER_PRIVATE)
    with pytest.raises(ValueError, match="signature"):
        store_worker_observation_batch(db, signed, now=NOW)
    assert db.scalar(select(WorkerObservationRecord)) is None


def test_revoked_key_is_rejected(db):
    revoke_worker_public_key(db, worker_id=WORKER_ID, key_id=KEY_ID)
    db.commit()
    signed = sign_worker_observation_batch(make_batch(), PRIVATE)
    with pytest.raises(ValueError, match="signature"):
        store_worker_observation_batch(db, signed, now=NOW)


def test_wrong_task_digest_is_rejected(db):
    signed = sign_worker_observation_batch(
        make_batch(envelope_sha256="d" * 64), PRIVATE
    )
    with pytest.raises(ValueError, match="receipt"):
        store_worker_observation_batch(db, signed, now=NOW)


def test_unconsumed_receipt_is_rejected(db):
    receipt = db.query(WorkerTaskReceipt).filter_by(task_id=str(TASK_ID)).one()
    receipt.consumed_at = None
    db.commit()
    signed = sign_worker_observation_batch(make_batch(), PRIVATE)
    with pytest.raises(ValueError, match="receipt"):
        store_worker_observation_batch(db, signed, now=NOW)


def test_duplicate_observation_id_in_batch_is_rejected_by_schema(db):
    observation_id = uuid4()
    observation = WorkerObservation(
        observation_id=observation_id, kind="ip", value="203.0.113.8",
        source="passive_dns", observed_at=NOW,
    )
    with pytest.raises(ValueError, match="duplicate"):
        make_batch(observations=[observation, observation])


def test_future_observation_is_rejected_by_schema(db):
    future = WorkerObservation(
        observation_id=uuid4(), kind="hostname", value="future.example.test",
        source="passive_dns", observed_at=NOW + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="later"):
        make_batch(observations=[future])


def test_duplicate_persisted_observation_id_rejects_second_batch(db):
    observation_id = uuid4()
    observation = WorkerObservation(
        observation_id=observation_id, kind="hostname", value="one.example.test",
        source="passive_dns", observed_at=NOW,
    )
    first = sign_worker_observation_batch(make_batch(observations=[observation]), PRIVATE)
    assert store_worker_observation_batch(db, first, now=NOW) == 1
    db.commit()  # Persist the first batch before testing a conflicting transaction.
    second_observation = observation.model_copy(update={"value": "two.example.test"})
    second = sign_worker_observation_batch(make_batch(observations=[second_observation]), PRIVATE)
    with pytest.raises(ValueError, match="duplicate"):
        store_worker_observation_batch(db, second, now=NOW)
    db.rollback()
    records = db.scalars(select(WorkerObservationRecord)).all()
    assert len(records) == 1
    assert records[0].value == "one.example.test"



def test_observation_rows_are_append_only_at_database_level(db):
    db.execute(__import__("sqlalchemy").text("""
        CREATE TRIGGER worker_observations_no_update
        BEFORE UPDATE ON worker_observations
        BEGIN
            SELECT RAISE(ABORT, 'worker observations are append-only');
        END
    """))
    db.execute(__import__("sqlalchemy").text("""
        CREATE TRIGGER worker_observations_no_delete
        BEFORE DELETE ON worker_observations
        BEGIN
            SELECT RAISE(ABORT, 'worker observations are append-only');
        END
    """))
    signed = sign_worker_observation_batch(make_batch(), PRIVATE)
    store_worker_observation_batch(db, signed, now=NOW)
    db.commit()
    record = db.scalar(select(WorkerObservationRecord))
    with pytest.raises(Exception, match="append-only"):
        record.value = "tampered.example.test"
        db.flush()
    db.rollback()
    record = db.scalar(select(WorkerObservationRecord))
    assert record.value == "api.example.test"
    with pytest.raises(Exception, match="append-only"):
        db.delete(record)
        db.flush()
    db.rollback()
    assert db.scalar(select(WorkerObservationRecord)).value == "api.example.test"
