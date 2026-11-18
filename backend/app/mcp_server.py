"""Local, read-only MCP interface for the single-user SNAKE installation.

The MCP process is intended to be launched by OpenCode over stdio. It does not
listen on a network socket and does not perform target-network requests.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP
from sqlalchemy.orm import Session

from app.core.scope_policy import ScopePolicy
from app.core.security_signal_engine import analyze_security_signals
from app.db.database import SessionLocal
from app.db.models import (
    Authorization,
    Project,
    ScanJob,
    ScopeSnapshot,
    Target,
    User,
    WorkerObservationRecord,
    WorkerTaskReceipt,
)

mcp = FastMCP("snake")


def _operator_id() -> int:
    raw = os.environ.get("SNAKE_MCP_USER_ID", "").strip()
    if not raw.isdigit() or int(raw) < 1:
        raise RuntimeError(
            "SNAKE_MCP_USER_ID must identify the local SNAKE operator; "
            "configure it in the OpenCode MCP server environment."
        )
    return int(raw)


def _owned_user(db: Session) -> User:
    user = db.get(User, _operator_id())
    if user is None or not user.is_active:
        raise RuntimeError("Configured SNAKE MCP operator is missing or inactive.")
    return user


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _snapshot_status(db: Session, snapshot: ScopeSnapshot, operator_id: int) -> dict[str, Any]:
    reasons: list[str] = []
    project = db.query(Project).filter_by(
        id=snapshot.project_id, owner_id=operator_id
    ).first()
    if project is None:
        return {"valid": False, "reasons": ["project_not_owned"]}
    try:
        data = json.loads(snapshot.snapshot_json)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        import hashlib
        if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != snapshot.sha256:
            reasons.append("snapshot_integrity_mismatch")
    except (TypeError, ValueError):
        data = {}
        reasons.append("snapshot_integrity_mismatch")

    if snapshot.status != "active":
        reasons.append("snapshot_not_active")
    auth = db.get(Authorization, snapshot.authorization_id)
    now = datetime.now(timezone.utc)
    if auth is None or auth.project_id != snapshot.project_id or auth.status != "approved":
        reasons.append("authorization_not_approved")
    else:
        for raw, expired, not_started in (
            (auth.starts_at, False, True),
            (auth.expires_at, True, False),
        ):
            if raw:
                try:
                    boundary = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    if boundary.tzinfo is None:
                        boundary = boundary.replace(tzinfo=timezone.utc)
                    boundary = boundary.astimezone(timezone.utc)
                    if expired and now >= boundary:
                        reasons.append("authorization_expired")
                    if not_started and now < boundary:
                        reasons.append("authorization_not_started")
                except ValueError:
                    reasons.append("invalid_authorization_window")
        try:
            current_rules = json.loads(auth.scope_rules or "[]")
            saved_rules = data.get("approved_scope_rules")
            if not isinstance(current_rules, list) or not isinstance(saved_rules, list):
                reasons.append("invalid_authorization_scope_rules")
            elif sorted(current_rules) != sorted(saved_rules):
                reasons.append("authorization_scope_rules_changed")
        except (TypeError, ValueError):
            reasons.append("invalid_authorization_scope_rules")

    target = db.get(Target, snapshot.target_id)
    if target is None or target.project_id != snapshot.project_id:
        reasons.append("target_missing_or_moved")
    else:
        if target.target_type == "url":
            current_target = target.value
        elif target.target_type == "domain":
            from app.core.scope_policy import normalize_host
            try:
                current_target = "https://" + normalize_host(target.value)
            except ValueError:
                current_target = None
        else:
            current_target = None
        if current_target != data.get("target"):
            reasons.append("target_changed")
        rules = data.get("approved_scope_rules")
        if not isinstance(rules, list) or not current_target or not ScopePolicy(rules).check_url(current_target).allowed:
            reasons.append("target_no_longer_matches_snapshot_scope")

    if data.get("project_id") != snapshot.project_id or data.get("target_id") != snapshot.target_id:
        reasons.append("snapshot_resource_mismatch")
    if data.get("authorization_id") != snapshot.authorization_id:
        reasons.append("snapshot_authorization_mismatch")
    return {"valid": not reasons, "reasons": sorted(set(reasons))}


@mcp.tool()
def snake_list_projects() -> str:
    """List projects owned by the configured local SNAKE operator."""
    with SessionLocal() as db:
        operator = _owned_user(db)
        rows = db.query(Project).filter_by(owner_id=operator.id).order_by(Project.id.asc()).limit(200).all()
        return _json([{"project_id": row.id, "name": row.name, "description": row.description} for row in rows])


@mcp.tool()
def snake_list_authorized_targets(project_id: int) -> str:
    """List targets whose active scope snapshots still pass authorization revalidation."""
    with SessionLocal() as db:
        operator = _owned_user(db)
        project = db.query(Project).filter_by(id=project_id, owner_id=operator.id).first()
        if project is None:
            return _json({"error": "project_not_found"})
        rows = db.query(ScopeSnapshot).filter_by(
            project_id=project.id, status="active"
        ).order_by(ScopeSnapshot.id.desc()).limit(200).all()
        result = []
        seen: set[int] = set()
        for snapshot in rows:
            if snapshot.target_id in seen:
                continue
            status = _snapshot_status(db, snapshot, operator.id)
            if not status["valid"]:
                continue
            target = db.get(Target, snapshot.target_id)
            if target is None:
                continue
            seen.add(target.id)
            result.append({
                "target_id": target.id,
                "target": target.value,
                "target_type": target.target_type,
                "scope_snapshot_id": snapshot.id,
                "scope_snapshot_sha256": snapshot.sha256,
                "authorization_id": snapshot.authorization_id,
            })
        return _json(result)


@mcp.tool()
def snake_list_scan_jobs(project_id: int) -> str:
    """List persisted scan-job records for an owned project; queued does not mean running."""
    with SessionLocal() as db:
        operator = _owned_user(db)
        project = db.query(Project).filter_by(id=project_id, owner_id=operator.id).first()
        if project is None:
            return _json({"error": "project_not_found"})
        rows = db.query(ScanJob).filter_by(
            project_id=project.id, created_by=operator.id
        ).order_by(ScanJob.id.desc()).limit(100).all()
        return _json([{
            "job_id": row.id,
            "target_id": row.target_id,
            "scope_snapshot_id": row.scope_snapshot_id,
            "profile": row.profile,
            "status": row.status,
            "execution_enabled": row.execution_enabled,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        } for row in rows])


@mcp.tool()
def snake_get_job_observations(job_id: int, limit: int = 100, offset: int = 0) -> str:
    """Read persisted, unconfirmed worker observations for an owned job."""
    if not 1 <= limit <= 200 or not 0 <= offset <= 1_000_000:
        return _json({"error": "invalid_pagination"})
    with SessionLocal() as db:
        operator = _owned_user(db)
        job = db.query(ScanJob).join(Project, Project.id == ScanJob.project_id).filter(
            ScanJob.id == job_id, Project.owner_id == operator.id
        ).first()
        if job is None:
            return _json({"error": "scan_job_not_found"})
        query = db.query(WorkerObservationRecord).join(
            WorkerTaskReceipt, WorkerTaskReceipt.task_id == WorkerObservationRecord.task_id
        ).filter(
            WorkerTaskReceipt.job_id == job.id,
            WorkerObservationRecord.classification == "unconfirmed_observation",
        )
        total = query.count()
        rows = query.order_by(
            WorkerObservationRecord.received_at.desc(),
            WorkerObservationRecord.id.desc(),
        ).offset(offset).limit(limit).all()
        return _json({
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [{
                "observation_id": row.observation_id,
                "kind": row.kind,
                "value": row.value,
                "evidence": row.evidence,
                "source": row.source,
                "observed_at": row.observed_at.isoformat(),
                "received_at": row.received_at.isoformat(),
                "classification": row.classification,
            } for row in rows],
        })


@mcp.tool()
def snake_get_security_signals(job_id: int) -> str:
    """Extract deterministic, unconfirmed security leads from an owned job's stored evidence."""
    with SessionLocal() as db:
        operator = _owned_user(db)
        job = db.query(ScanJob).join(Project, Project.id == ScanJob.project_id).filter(
            ScanJob.id == job_id, Project.owner_id == operator.id
        ).first()
        if job is None:
            return _json({"error": "scan_job_not_found"})
        rows = db.query(WorkerObservationRecord).join(
            WorkerTaskReceipt, WorkerTaskReceipt.task_id == WorkerObservationRecord.task_id
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
        return _json(analyze_security_signals(observations).model_dump())


if __name__ == "__main__":
    mcp.run(transport="stdio")
