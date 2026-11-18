"""Local MCP interface for the single-user SNAKE installation.

The MCP process is launched by OpenCode over stdio. It has no network listener;
its single bounded HTTP collection tool is constrained by active scope snapshots.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from uuid import uuid4
from typing import Any
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from sqlalchemy.orm import Session

from app.core.scope_policy import ScopePolicy
from app.core.security_signal_engine import analyze_security_signals
from app.core.local_http_collector import CollectionError, collect_http
from app.db.database import SessionLocal
from app.db.models import (
    AuditEvent,
    Authorization,
    LocalReconObservation,
    LocalReconRun,
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


def _redact_url_query(value: str) -> str:
    parsed = urlsplit(value)
    return parsed._replace(query="", fragment="").geturl()


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

    if snapshot.status != "active" or snapshot.revoked_at is not None:
        reasons.append("snapshot_not_active")
    if data.get("execution_enabled") is not False:
        reasons.append("unexpected_snapshot_execution_flag")
    now = datetime.now(timezone.utc)
    if snapshot.expires_at:
        try:
            snapshot_expiry = datetime.fromisoformat(snapshot.expires_at.replace("Z", "+00:00"))
            if snapshot_expiry.tzinfo is None:
                snapshot_expiry = snapshot_expiry.replace(tzinfo=timezone.utc)
            if now >= snapshot_expiry.astimezone(timezone.utc):
                reasons.append("authorization_expired")
        except ValueError:
            reasons.append("invalid_snapshot_expiry")
    auth = db.get(Authorization, snapshot.authorization_id)
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
                "target": _redact_url_query(target.value) if target.target_type == "url" else target.value,
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


@mcp.tool()
def snake_collect_http(target_id: int, scope_snapshot_id: int, max_pages: int = 5) -> str:
    """Run bounded, unauthenticated HTTP GET collection for an approved target.

    The model supplies target and snapshot IDs only, never a URL. Collection
    is limited to public DNS destinations, the approved hostname scope, at
    most 10 pages, 256 KiB per response, and three redirects.
    """
    if not 1 <= max_pages <= 10:
        return _json({"error": "max_pages_must_be_between_1_and_10"})
    with SessionLocal() as db:
        operator = _owned_user(db)
        target = db.query(Target).join(
            Project, Project.id == Target.project_id
        ).filter(
            Target.id == target_id,
            Project.owner_id == operator.id,
        ).first()
        if target is None:
            return _json({"error": "target_not_found"})
        snapshot = db.query(ScopeSnapshot).filter_by(
            id=scope_snapshot_id,
            target_id=target.id,
            project_id=target.project_id,
        ).first()
        if snapshot is None:
            return _json({"error": "scope_snapshot_not_found"})
        validation = _snapshot_status(db, snapshot, operator.id)
        if not validation["valid"]:
            return _json({
                "error": "scope_snapshot_not_valid",
                "reasons": validation["reasons"],
            })
        latest_run = db.query(LocalReconRun).filter_by(
            target_id=target.id,
            created_by=operator.id,
        ).order_by(LocalReconRun.id.desc()).first()
        if latest_run is not None:
            last_completed = latest_run.completed_at
            if last_completed.tzinfo is None:
                last_completed = last_completed.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - last_completed.astimezone(timezone.utc)).total_seconds()
            if elapsed < 30:
                return _json({
                    "error": "target_cooldown_active",
                    "retry_after_seconds": max(1, int(30 - elapsed) + 1),
                })

        snapshot_data = json.loads(snapshot.snapshot_json)
        approved_rules = snapshot_data.get("approved_scope_rules")
        target_url = snapshot_data.get("target")
        if not isinstance(approved_rules, list) or not target_url:
            return _json({"error": "invalid_scope_snapshot_payload"})

        started = datetime.now(timezone.utc)
        report = None
        collection_error = None
        try:
            report = collect_http(
                target_url,
                approved_rules,
                max_pages=max_pages,
                allow_private_networks=False,
            )
        except (CollectionError, ValueError) as exc:
            collection_error = str(exc)[:160]
        completed = datetime.now(timezone.utc)

        status = "failed" if report is None or report.pages_requested == 0 else (
            "partial" if report.skipped else "completed"
        )
        observation_rows = []
        if report is not None:
            for page in report.observations:
                host = (urlsplit(page.url).hostname or "").lower().rstrip(".")
                metadata = (
                    f"status={page.status_code};content_type={page.content_type[:120]};"
                    f"body_bytes={page.body_bytes};body_limit={report.body_limit_bytes}"
                )
                observation_rows.append(LocalReconObservation(
                    observation_id=str(uuid4()),
                    kind="url",
                    value=page.url[:2048],
                    evidence=metadata,
                    host_key=host,
                    observed_at=completed,
                    classification="unconfirmed_observation",
                ))
                for name, value in page.headers:
                    observation_rows.append(LocalReconObservation(
                        observation_id=str(uuid4()),
                        kind="http_header",
                        value=f"{name}: {value}"[:2048],
                        evidence=metadata,
                        host_key=host,
                        observed_at=completed,
                        classification="unconfirmed_observation",
                    ))

        if len(observation_rows) > 250:
            observation_rows = observation_rows[:250]
            status = "partial"
        run = LocalReconRun(
            project_id=target.project_id,
            target_id=target.id,
            scope_snapshot_id=snapshot.id,
            created_by=operator.id,
            status=status,
            pages_requested=report.pages_requested if report else 0,
            observation_count=len(observation_rows),
            started_at=started,
            completed_at=completed,
            execution_enabled=False,
        )
        db.add(run)
        db.flush()
        for item in observation_rows:
            item.run_id = run.id
            db.add(item)
        skipped_count = len(report.skipped) if report else 0
        db.add(AuditEvent(
            actor_user_id=operator.id,
            action="local_recon.completed" if status != "failed" else "local_recon.failed",
            resource_type="local_recon_run",
            resource_id=str(run.id),
            details=(
                f"target_id={target.id};scope_snapshot_id={snapshot.id};"
                f"pages={run.pages_requested};observations={run.observation_count};"
                f"skipped={skipped_count};execution_enabled=false"
            ),
        ))
        db.commit()
        db.refresh(run)
        return _json({
            "run_id": run.id,
            "status": run.status,
            "target_id": run.target_id,
            "scope_snapshot_id": run.scope_snapshot_id,
            "pages_requested": run.pages_requested,
            "observation_count": run.observation_count,
            "skipped": [(_redact_url_query(url), reason) for url, reason in report.skipped[:20]] if report else [],
            "error": collection_error,
            "execution_enabled": False,
            "note": "Metadata-only evidence; response bodies and cookie values are never stored.",
        })


@mcp.tool()
def snake_get_local_recon_evidence(run_id: int, limit: int = 200) -> str:
    """Read redacted HTTP observations and deterministic signals from an owned local recon run."""
    if not 1 <= limit <= 250:
        return _json({"error": "limit_must_be_between_1_and_250"})
    with SessionLocal() as db:
        operator = _owned_user(db)
        run = db.query(LocalReconRun).join(
            Project, Project.id == LocalReconRun.project_id
        ).filter(
            LocalReconRun.id == run_id,
            Project.owner_id == operator.id,
        ).first()
        if run is None:
            return _json({"error": "local_recon_run_not_found"})
        rows = db.query(LocalReconObservation).filter_by(
            run_id=run.id,
            classification="unconfirmed_observation",
        ).order_by(LocalReconObservation.id.asc()).limit(limit).all()
        observations = [{
            "observation_id": row.observation_id,
            "kind": row.kind,
            "value": row.value,
            "evidence": row.evidence,
            "host_key": row.host_key,
            "classification": row.classification,
        } for row in rows]
        signals = analyze_security_signals(observations).model_dump()
        return _json({
            "run_id": run.id,
            "status": run.status,
            "target_id": run.target_id,
            "scope_snapshot_id": run.scope_snapshot_id,
            "pages_requested": run.pages_requested,
            "observation_count": run.observation_count,
            "returned_observation_count": len(observations),
            "observations": observations,
            "security_signals": signals,
            "execution_enabled": False,
        })


@mcp.tool()
def snake_list_local_recon_runs(project_id: int, limit: int = 50) -> str:
    """List recent local recon runs for an owned project."""
    if not 1 <= limit <= 100:
        return _json({"error": "limit_must_be_between_1_and_100"})
    with SessionLocal() as db:
        operator = _owned_user(db)
        project = db.query(Project).filter_by(
            id=project_id,
            owner_id=operator.id,
        ).first()
        if project is None:
            return _json({"error": "project_not_found"})
        rows = db.query(LocalReconRun).filter_by(
            project_id=project.id,
            created_by=operator.id,
        ).order_by(LocalReconRun.id.desc()).limit(limit).all()
        result = []
        for row in rows:
            target = db.get(Target, row.target_id)
            result.append({
                "run_id": row.id,
                "target_id": row.target_id,
                "target": _redact_url_query(target.value) if target and target.target_type == "url" else (target.value if target else None),
                "scope_snapshot_id": row.scope_snapshot_id,
                "status": row.status,
                "pages_requested": row.pages_requested,
                "observation_count": row.observation_count,
                "started_at": row.started_at.isoformat(),
                "completed_at": row.completed_at.isoformat(),
                "execution_enabled": row.execution_enabled,
            })
        return _json(result)


if __name__ == "__main__":
    mcp.run(transport="stdio")
