from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.worker_claims import envelope_digest, reserve_task_receipt
from app.core.worker_dispatch_attempts import begin_dispatch_attempt, finish_dispatch_attempt
from app.core.worker_protocol import WorkerTaskEnvelope
from app.db.models import (
    ScanJob, WorkerTaskReceipt, WorkerKey, WorkerDispatchAttempt,
)


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    for model in (ScanJob, WorkerTaskReceipt, WorkerKey, WorkerDispatchAttempt):
        model.__table__.create(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def setup_task(db):
    now = datetime.now(timezone.utc)
    db.add(ScanJob(
        id=91, project_id=1, target_id=1, scope_snapshot_id=7,
        created_by=1, profile="passive_recon", status="queued",
        execution_enabled=False,
    ))
    db.add(WorkerKey(
        worker_id="worker-a", key_id="key-a", public_key_b64="placeholder",
        fingerprint_sha256="b" * 64, status="active",
    ))
    db.commit()
    envelope = WorkerTaskEnvelope(
        task_id=__import__("uuid").uuid4(), job_id=91, scope_snapshot_id=7,
        scope_snapshot_sha256="a" * 64, profile="passive_recon",
        target_url="https://example.org/", issued_at=now,
        expires_at=now + timedelta(minutes=2), execution_enabled=False,
    )
    reserve_task_receipt(db, envelope, worker_id="worker-a", key_id="key-a", now=now)
    return envelope, now


def test_attempt_is_persisted_before_delivery_and_can_be_closed(db):
    envelope, now = setup_task(db)
    digest = envelope_digest(envelope)
    attempt = begin_dispatch_attempt(
        db, task_id=str(envelope.task_id), worker_id="worker-a",
        key_id="key-a", envelope_sha256=digest, now=now,
    )
    assert attempt.status == "started"
    assert finish_dispatch_attempt(db, attempt.id, "delivered", now=now)
    db.refresh(attempt)
    assert attempt.status == "delivered"
    assert attempt.completed_at is not None
    assert not finish_dispatch_attempt(db, attempt.id, "failed", now=now)


def test_only_definite_failure_allows_same_task_retry(db):
    envelope, now = setup_task(db)
    args = dict(
        task_id=str(envelope.task_id), worker_id="worker-a", key_id="key-a",
        envelope_sha256=envelope_digest(envelope), now=now,
    )
    first = begin_dispatch_attempt(db, **args)
    assert finish_dispatch_attempt(db, first.id, "failed", error_code="connect_refused", now=now)
    second = begin_dispatch_attempt(db, **args)
    assert second.attempt_number == 2
    assert finish_dispatch_attempt(db, second.id, "unknown", error_code="read_timeout", now=now)
    with pytest.raises(ValueError, match="not confirmed failed"):
        begin_dispatch_attempt(db, **args)


def test_unknown_outcome_is_not_retried(db):
    envelope, now = setup_task(db)
    args = dict(
        task_id=str(envelope.task_id), worker_id="worker-a", key_id="key-a",
        envelope_sha256=envelope_digest(envelope), now=now,
    )
    attempt = begin_dispatch_attempt(db, **args)
    finish_dispatch_attempt(db, attempt.id, "unknown", error_code="timeout", now=now)
    with pytest.raises(ValueError, match="not confirmed failed"):
        begin_dispatch_attempt(db, **args)


def test_revoked_worker_key_cannot_start_attempt(db):
    envelope, now = setup_task(db)
    key = db.query(WorkerKey).filter_by(worker_id="worker-a").one()
    key.status = "revoked"
    db.commit()
    with pytest.raises(ValueError, match="not registered and active"):
        begin_dispatch_attempt(
            db, task_id=str(envelope.task_id), worker_id="worker-a",
            key_id="key-a", envelope_sha256=envelope_digest(envelope), now=now,
        )


def test_attempt_rejects_wrong_digest(db):
    envelope, now = setup_task(db)
    with pytest.raises(ValueError, match="receipt or digest"):
        begin_dispatch_attempt(
            db, task_id=str(envelope.task_id), worker_id="worker-a",
            key_id="key-a", envelope_sha256="f" * 64, now=now,
        )



def test_attempt_cannot_be_routed_to_different_worker_identity(db):
    envelope, now = setup_task(db)
    with pytest.raises(ValueError, match="does not match"):
        begin_dispatch_attempt(
            db, task_id=str(envelope.task_id), worker_id="worker-b",
            key_id="key-b", envelope_sha256=envelope_digest(envelope), now=now,
        )
