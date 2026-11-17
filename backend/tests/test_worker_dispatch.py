from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core import worker_dispatch


class FakeDB:
    def __init__(self, objects):
        self.objects = objects

    def get(self, model, key):
        return self.objects.get((model.__name__, key))


def make_state():
    from app.db.models import Authorization, Project, ScanJob, ScopeSnapshot, Target

    now = datetime.now(timezone.utc)
    job = SimpleNamespace(
        id=11, project_id=2, target_id=3, scope_snapshot_id=4,
        created_by=5, status="queued", execution_enabled=False,
        profile="passive_recon",
    )
    snapshot = SimpleNamespace(
        id=4, project_id=2, target_id=3, authorization_id=6,
        snapshot_json='{"target":"https://example.org"}',
        sha256="b" * 64, status="active",
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )
    project = SimpleNamespace(id=2, owner_id=5)
    target = SimpleNamespace(id=3, project_id=2)
    authorization = SimpleNamespace(
        id=6, project_id=2, status="approved",
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )
    objects = {
        ("ScanJob", 11): job,
        ("ScopeSnapshot", 4): snapshot,
        ("Project", 2): project,
        ("Target", 3): target,
        ("Authorization", 6): authorization,
    }
    return FakeDB(objects), job, snapshot, now


def test_dispatch_gate_builds_short_lived_disabled_envelope(monkeypatch):
    db, job, snapshot, now = make_state()
    monkeypatch.setattr(worker_dispatch, "validate_snapshot_for_queue", lambda *args: [])
    envelope = worker_dispatch.prepare_dispatch_envelope(db, job.id, now=now, ttl_seconds=60)
    assert envelope.execution_enabled is False
    assert envelope.job_id == job.id
    assert envelope.scope_snapshot_sha256 == snapshot.sha256
    assert envelope.expires_at <= now + timedelta(seconds=60)


def test_dispatch_gate_rejects_invalid_scope(monkeypatch):
    db, job, _, now = make_state()
    monkeypatch.setattr(
        worker_dispatch, "validate_snapshot_for_queue",
        lambda *args: ["authorization_not_approved"],
    )
    with pytest.raises(HTTPException) as error:
        worker_dispatch.prepare_dispatch_envelope(db, job.id, now=now)
    assert error.value.status_code == 409


def test_dispatch_gate_rejects_nonqueued_or_enabled_jobs(monkeypatch):
    db, job, _, now = make_state()
    monkeypatch.setattr(worker_dispatch, "validate_snapshot_for_queue", lambda *args: [])
    job.status = "cancelled"
    with pytest.raises(HTTPException) as error:
        worker_dispatch.prepare_dispatch_envelope(db, job.id, now=now)
    assert error.value.status_code == 409
    job.status = "queued"
    job.execution_enabled = True
    with pytest.raises(HTTPException) as error:
        worker_dispatch.prepare_dispatch_envelope(db, job.id, now=now)
    assert error.value.status_code == 409


def test_dispatch_gate_caps_ttl_and_respects_authorization_expiry(monkeypatch):
    db, job, _, now = make_state()
    monkeypatch.setattr(worker_dispatch, "validate_snapshot_for_queue", lambda *args: [])
    with pytest.raises(ValueError):
        worker_dispatch.prepare_dispatch_envelope(db, job.id, now=now, ttl_seconds=301)
    authorization = db.get(__import__("app.db.models", fromlist=["Authorization"]).Authorization, 6)
    authorization.expires_at = (now + timedelta(seconds=10)).isoformat()
    envelope = worker_dispatch.prepare_dispatch_envelope(db, job.id, now=now, ttl_seconds=120)
    assert envelope.expires_at <= now + timedelta(seconds=10)
