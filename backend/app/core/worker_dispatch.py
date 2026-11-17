"""Database-backed dispatch gate.

This module can prepare a short-lived, non-executable envelope for inspection.
It does NOT claim a job, contact a worker, resolve DNS, or perform network I/O.
"""
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.api.scan_jobs import validate_snapshot_for_queue
from app.core.worker_protocol import WorkerTaskEnvelope, ensure_not_expired
from app.db.models import Authorization, Project, ScanJob, ScopeSnapshot, Target

MAX_TASK_TTL_SECONDS = 300


def _parse_boundary(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def prepare_dispatch_envelope(
    db: Session,
    job_id: int,
    *,
    now: datetime | None = None,
    ttl_seconds: int = 120,
) -> WorkerTaskEnvelope:
    """Revalidate persisted state and return a disabled envelope; never dispatch it."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("current time must be timezone-aware")
    if not 1 <= ttl_seconds <= MAX_TASK_TTL_SECONDS:
        raise ValueError("ttl_seconds must be between 1 and 300")

    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status != "queued":
        raise HTTPException(status_code=409, detail="Only queued jobs may pass the dispatch gate")
    if job.execution_enabled is not False:
        raise HTTPException(status_code=409, detail="Job execution is disabled")
    if job.profile != "passive_recon":
        raise HTTPException(status_code=409, detail="Unsupported worker profile")

    project = db.get(Project, job.project_id)
    snapshot = db.get(ScopeSnapshot, job.scope_snapshot_id)
    target = db.get(Target, job.target_id)
    if (project is None or project.owner_id != job.created_by
            or snapshot is None or target is None
            or snapshot.project_id != job.project_id
            or snapshot.target_id != job.target_id
            or target.project_id != job.project_id):
        raise HTTPException(status_code=409, detail="Job resource ownership or linkage changed")

    reasons = validate_snapshot_for_queue(db, snapshot, job.created_by)
    if reasons:
        raise HTTPException(status_code=409, detail={
            "message": "Scope snapshot failed dispatch-time validation",
            "reasons": reasons,
        })

    try:
        snapshot_data = json.loads(snapshot.snapshot_json)
    except (TypeError, ValueError):
        raise HTTPException(status_code=409, detail="Invalid scope snapshot")

    authorization = db.get(Authorization, snapshot.authorization_id)
    if authorization is None:
        raise HTTPException(status_code=409, detail="Authorization record missing")

    # Expiry is bounded by both the short task TTL and the authorization/snapshot expiry.
    expires_at = current.astimezone(timezone.utc) + timedelta(seconds=ttl_seconds)
    for boundary_text in (snapshot.expires_at, authorization.expires_at):
        boundary = _parse_boundary(boundary_text)
        if boundary is not None:
            expires_at = min(expires_at, boundary)
    if expires_at <= current.astimezone(timezone.utc):
        raise HTTPException(status_code=409, detail="Authorization expires before task can be issued")

    envelope = WorkerTaskEnvelope(
        task_id=uuid4(),
        job_id=job.id,
        scope_snapshot_id=snapshot.id,
        scope_snapshot_sha256=snapshot.sha256,
        profile="passive_recon",
        target_url=snapshot_data["target"],
        issued_at=current.astimezone(timezone.utc),
        expires_at=expires_at,
        execution_enabled=False,
    )
    ensure_not_expired(envelope, now=current)
    return envelope
