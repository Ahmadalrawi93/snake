from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.worker_claims import consume_task_receipt, envelope_digest, reserve_task_receipt
from app.core.worker_protocol import WorkerTaskEnvelope
from app.db.models import ScanJob, WorkerTaskReceipt


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    ScanJob.__table__.create(engine)
    WorkerTaskReceipt.__table__.create(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def make_job(db):
    job = ScanJob(
        id=41, project_id=1, target_id=1, scope_snapshot_id=7,
        created_by=1, profile="passive_recon", status="queued",
        execution_enabled=False,
    )
    db.add(job)
    db.commit()
    return job


def make_envelope(job_id=41):
    now = datetime.now(timezone.utc)
    return WorkerTaskEnvelope(
        task_id=uuid4(), job_id=job_id, scope_snapshot_id=7,
        scope_snapshot_sha256="a" * 64, profile="passive_recon",
        target_url="https://example.org/",
        issued_at=now, expires_at=now + timedelta(minutes=2),
        execution_enabled=False,
    )


def test_reservation_is_atomic_and_durable(db):
    job = make_job(db)
    envelope = make_envelope()
    receipt = reserve_task_receipt(db, envelope, worker_id="worker-test", key_id="key-test")
    db.refresh(job)
    assert job.status == "dispatch_reserved"
    assert receipt.task_id == str(envelope.task_id)
    assert receipt.envelope_sha256 == envelope_digest(envelope)


def test_job_cannot_be_reserved_twice_even_with_new_task_id(db):
    make_job(db)
    reserve_task_receipt(db, make_envelope(), worker_id="worker-test", key_id="key-test")
    with pytest.raises(ValueError, match="no longer eligible"):
        reserve_task_receipt(db, make_envelope(), worker_id="worker-test", key_id="key-test")


def test_task_receipt_can_be_consumed_only_once(db):
    make_job(db)
    envelope = make_envelope()
    reserve_task_receipt(db, envelope, worker_id="worker-test", key_id="key-test")
    digest = envelope_digest(envelope)
    assert consume_task_receipt(db, str(envelope.task_id), digest)
    assert not consume_task_receipt(db, str(envelope.task_id), digest)


def test_receipt_rejects_wrong_digest_and_expired_task(db):
    make_job(db)
    envelope = make_envelope()
    reserve_task_receipt(db, envelope, worker_id="worker-test", key_id="key-test")
    assert not consume_task_receipt(db, str(envelope.task_id), "0" * 64)
    future = datetime.now(timezone.utc) + timedelta(minutes=5)
    assert not consume_task_receipt(db, str(envelope.task_id), envelope_digest(envelope), now=future)


def test_reservation_rejects_expired_envelope(db):
    make_job(db)
    envelope = make_envelope()
    with pytest.raises(ValueError, match="expired"):
        reserve_task_receipt(db, envelope, worker_id="worker-test", key_id="key-test", now=envelope.expires_at + timedelta(seconds=1))


def test_reservation_requires_worker_identity(db):
    make_job(db)
    with pytest.raises(ValueError, match="worker identity"):
        reserve_task_receipt(db, make_envelope())
