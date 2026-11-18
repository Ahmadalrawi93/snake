"""Persisted scan-job control plane. Jobs are queued records only; no worker consumes them."""
import hashlib
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.scope_policy import ScopePolicy, normalize_host
from app.core.security_signal_engine import SecuritySignalReport, analyze_security_signals
from app.db.database import get_db
from app.db.models import (
    AuditEvent, Authorization, Project, ScanJob, ScopeSnapshot, Target, User,
    WorkerObservationRecord, WorkerTaskReceipt,
)

router = APIRouter(prefix="/api/v1", tags=["scan jobs"])
ALLOWED_PROFILES = {"passive_recon"}


class ScanJobCreate(BaseModel):
    profile: str = Field(default="passive_recon", pattern="^passive_recon$")


class ScanJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    target_id: int
    scope_snapshot_id: int
    profile: str
    status: str
    execution_enabled: bool
    created_at: datetime
    updated_at: datetime


def _target_url(target: Target) -> str | None:
    if target.target_type == "url":
        return target.value
    if target.target_type == "domain":
        try:
            return "https://" + normalize_host(target.value)
        except ValueError:
            return None
    return None


def validate_snapshot_for_queue(db: Session, snapshot: ScopeSnapshot, owner_id: int) -> list[str]:
    """Revalidate ownership, integrity, authorization, target and allowlist at enqueue time."""
    reasons: list[str] = []
    project = db.query(Project).filter_by(id=snapshot.project_id, owner_id=owner_id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Scope snapshot not found")

    try:
        data = json.loads(snapshot.snapshot_json)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != snapshot.sha256:
            reasons.append("snapshot_integrity_mismatch")
    except (TypeError, ValueError):
        data = {}
        reasons.append("snapshot_integrity_mismatch")

    if snapshot.status != "active":
        reasons.append("snapshot_not_active")
    if data.get("execution_enabled") is not False:
        reasons.append("unexpected_snapshot_execution_flag")

    now = datetime.now(timezone.utc)
    if snapshot.expires_at:
        try:
            expiry = datetime.fromisoformat(snapshot.expires_at.replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if now >= expiry.astimezone(timezone.utc):
                reasons.append("authorization_expired")
        except ValueError:
            reasons.append("invalid_snapshot_expiry")

    authorization = db.get(Authorization, snapshot.authorization_id)
    if (authorization is None or authorization.project_id != snapshot.project_id
            or authorization.status != "approved"):
        reasons.append("authorization_not_approved")
    else:
        # Re-check the complete authorization window and the exact reviewed rules.
        for field, reason, predicate in (
            (authorization.starts_at, "authorization_not_started",
             lambda value: now < value),
            (authorization.expires_at, "authorization_expired",
             lambda value: now >= value),
        ):
            if field:
                try:
                    boundary = datetime.fromisoformat(field.replace("Z", "+00:00"))
                    if boundary.tzinfo is None:
                        boundary = boundary.replace(tzinfo=timezone.utc)
                    if predicate(boundary.astimezone(timezone.utc)):
                        reasons.append(reason)
                except ValueError:
                    reasons.append("invalid_authorization_window")
        try:
            current_rules = json.loads(authorization.scope_rules or "[]")
            snapshot_rules = data.get("approved_scope_rules")
            if (not isinstance(current_rules, list) or not isinstance(snapshot_rules, list)
                    or sorted(current_rules) != sorted(snapshot_rules)):
                reasons.append("authorization_scope_rules_changed")
        except (TypeError, ValueError):
            reasons.append("invalid_authorization_scope_rules")

    target = db.get(Target, snapshot.target_id)
    if target is None or target.project_id != snapshot.project_id:
        reasons.append("target_missing_or_moved")
    else:
        current_url = _target_url(target)
        if current_url != data.get("target"):
            reasons.append("target_changed")
        rules = data.get("approved_scope_rules")
        if not isinstance(rules, list) or not current_url or not ScopePolicy(rules).check_url(current_url).allowed:
            reasons.append("target_no_longer_matches_snapshot_scope")

    if data.get("project_id") != snapshot.project_id or data.get("target_id") != snapshot.target_id:
        reasons.append("snapshot_resource_mismatch")
    if data.get("authorization_id") != snapshot.authorization_id:
        reasons.append("snapshot_authorization_mismatch")
    return reasons


@router.post("/scope-snapshots/{snapshot_id}/scan-jobs",
             response_model=ScanJobRead, status_code=201)
def create_scan_job(
    snapshot_id: int,
    payload: ScanJobCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    if payload.profile not in ALLOWED_PROFILES:
        raise HTTPException(status_code=422, detail="Unsupported scan profile")
    snapshot = db.get(ScopeSnapshot, snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Scope snapshot not found")
    reasons = validate_snapshot_for_queue(db, snapshot, actor.id)
    if reasons:
        raise HTTPException(status_code=409, detail={"message": "Scope snapshot is not queueable", "reasons": reasons})

    job = ScanJob(
        project_id=snapshot.project_id,
        target_id=snapshot.target_id,
        scope_snapshot_id=snapshot.id,
        created_by=actor.id,
        profile=payload.profile,
        status="queued",
        execution_enabled=False,
    )
    db.add(job)
    db.flush()
    db.add(AuditEvent(
        actor_user_id=actor.id,
        action="scan_job.queued",
        resource_type="scan_job",
        resource_id=str(job.id),
        details=f"profile={job.profile}; execution_enabled=false; worker_dispatch=disabled",
    ))
    db.commit()
    db.refresh(job)
    return job


@router.get("/projects/{project_id}/scan-jobs", response_model=list[ScanJobRead])
def list_scan_jobs(
    project_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return db.query(ScanJob).filter_by(project_id=project_id, created_by=actor.id).order_by(
        ScanJob.id.desc()
    ).limit(200).all()


@router.get("/scan-jobs/{job_id}", response_model=ScanJobRead)
def get_scan_job(
    job_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    job = db.query(ScanJob).join(Project, Project.id == ScanJob.project_id).filter(
        ScanJob.id == job_id, Project.owner_id == actor.id
    ).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.post("/scan-jobs/{job_id}/cancel", response_model=ScanJobRead)
def cancel_scan_job(
    job_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    job = db.query(ScanJob).join(Project, Project.id == ScanJob.project_id).filter(
        ScanJob.id == job_id, Project.owner_id == actor.id, ScanJob.created_by == actor.id
    ).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status != "queued":
        raise HTTPException(status_code=409, detail="Only queued jobs can be cancelled")
    job.status = "cancelled"
    job.updated_at = datetime.now(timezone.utc)
    db.add(AuditEvent(
        actor_user_id=actor.id,
        action="scan_job.cancelled",
        resource_type="scan_job",
        resource_id=str(job.id),
        details="Cancelled before worker dispatch; execution is disabled.",
    ))
    db.commit()
    db.refresh(job)
    return job



class WorkerObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    observation_id: str
    task_id: str
    worker_id: str
    key_id: str
    envelope_sha256: str
    batch_sha256: str
    kind: str
    value: str
    evidence: str
    source: str
    observed_at: datetime
    collected_at: datetime
    received_at: datetime
    classification: str


class WorkerObservationPage(BaseModel):
    items: list[WorkerObservationRead]
    total: int
    limit: int
    offset: int


@router.get("/scan-jobs/{job_id}/observations", response_model=WorkerObservationPage)
def list_scan_job_observations(
    job_id: int,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=1000000),
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    """Return unconfirmed worker evidence only to the owning project user."""
    job = db.query(ScanJob).join(
        Project, Project.id == ScanJob.project_id
    ).filter(
        ScanJob.id == job_id,
        Project.owner_id == actor.id,
    ).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")

    query = db.query(WorkerObservationRecord).join(
        WorkerTaskReceipt,
        WorkerTaskReceipt.task_id == WorkerObservationRecord.task_id,
    ).filter(WorkerTaskReceipt.job_id == job.id)
    total = query.count()
    rows = query.order_by(
        WorkerObservationRecord.received_at.desc(),
        WorkerObservationRecord.id.desc(),
    ).offset(offset).limit(limit).all()
    return WorkerObservationPage(
        items=rows,
        total=total,
        limit=limit,
        offset=offset,
    )



@router.get("/scan-jobs/{job_id}/security-signals", response_model=SecuritySignalReport)
def get_scan_job_security_signals(
    job_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    """Analyze only persisted worker-signed observations for the owned scan job."""
    job = db.query(ScanJob).join(
        Project, Project.id == ScanJob.project_id
    ).filter(
        ScanJob.id == job_id,
        Project.owner_id == actor.id,
    ).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")

    rows = db.query(WorkerObservationRecord).join(
        WorkerTaskReceipt,
        WorkerTaskReceipt.task_id == WorkerObservationRecord.task_id,
    ).filter(
        WorkerTaskReceipt.job_id == job.id,
        WorkerObservationRecord.classification == "unconfirmed_observation",
    ).order_by(
        WorkerObservationRecord.received_at.asc(),
        WorkerObservationRecord.id.asc(),
    ).limit(5000).all()

    observations = []
    for row in rows:
        host_key = ""
        if row.kind == "http_header" and row.evidence.startswith("hostname="):
            host_key = row.evidence.split(";", 1)[0].partition("=")[2]
        observations.append({
            "observation_id": row.observation_id,
            "kind": row.kind,
            "value": row.value,
            "evidence": row.evidence,
            "host_key": host_key,
        })
    return analyze_security_signals(observations)
