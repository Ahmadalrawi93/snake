import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.scope_policy import ScopePolicy
from app.db.database import get_db
from app.db.models import Authorization, AuditEvent, Project, ScopeSnapshot, Target, User

router = APIRouter(prefix="/api/v1", tags=["scope snapshots"])

class SnapshotRead(BaseModel):
    id: int
    project_id: int
    target_id: int
    authorization_id: int
    snapshot: dict
    sha256: str
    status: str
    created_at: datetime
    expires_at: str | None

def parse_time(value: str | None):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        raise HTTPException(status_code=422, detail="Authorization dates must be ISO-8601 timestamps")

def serialize_snapshot(row: ScopeSnapshot):
    return SnapshotRead(
        id=row.id, project_id=row.project_id, target_id=row.target_id,
        authorization_id=row.authorization_id, snapshot=json.loads(row.snapshot_json),
        sha256=row.sha256, status=row.status, created_at=row.created_at,
        expires_at=row.expires_at,
    )

@router.post("/projects/{project_id}/targets/{target_id}/scope-snapshots",
             response_model=SnapshotRead, status_code=201)
def create_scope_snapshot(
    project_id: int,
    target_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    target = db.query(Target).filter_by(id=target_id, project_id=project_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    if target.target_type == "url":
        target_url = target.value
    elif target.target_type == "domain":
        target_url = "https://" + target.value
    else:
        raise HTTPException(status_code=422, detail="Only URL and domain targets are supported for scope snapshots")

    parsed = urlsplit(target_url)
    if not parsed.hostname:
        raise HTTPException(status_code=422, detail="Target must contain a valid hostname")

    now = datetime.now(timezone.utc)
    authorizations = db.query(Authorization).filter_by(
        project_id=project_id, status="approved"
    ).order_by(Authorization.id.desc()).all()

    matching = None
    for auth in authorizations:
        starts = parse_time(auth.starts_at)
        expires = parse_time(auth.expires_at)
        if starts and now < starts:
            continue
        if expires and now >= expires:
            continue
        try:
            rules = json.loads(auth.scope_rules or "[]")
        except json.JSONDecodeError:
            continue
        decision = ScopePolicy(rules).check_url(target_url)
        if decision.allowed:
            matching = (auth, rules, decision.hostname, expires)
            break

    if matching is None:
        raise HTTPException(status_code=403, detail="No currently valid approved authorization covers this target")

    auth, rules, hostname, expires = matching
    snapshot_data = {
        "schema_version": 1,
        "project_id": project_id,
        "target_id": target.id,
        "target": target_url,
        "hostname": hostname,
        "authorization_id": auth.id,
        "authorization_reference": auth.reference,
        "authorization_status": "approved",
        "approved_scope_rules": sorted(rules),
        "created_at": now.isoformat(),
        "authorization_expires_at": expires.isoformat() if expires else None,
        "policy": "hostname-allowlist-v1",
        "execution_enabled": False,
    }
    canonical = json.dumps(snapshot_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    row = ScopeSnapshot(
        project_id=project_id, target_id=target.id, authorization_id=auth.id,
        created_by=actor.id, snapshot_json=canonical, sha256=digest,
        status="active", expires_at=expires.isoformat() if expires else None,
    )
    db.add(row)
    db.flush()
    db.add(AuditEvent(
        actor_user_id=actor.id, action="scope_snapshot.created",
        resource_type="scope_snapshot", resource_id=str(row.id),
        details=f"sha256={digest}; execution_enabled=false",
    ))
    db.commit()
    db.refresh(row)
    return serialize_snapshot(row)

@router.get("/projects/{project_id}/scope-snapshots", response_model=list[SnapshotRead])
def list_scope_snapshots(
    project_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    rows = db.query(ScopeSnapshot).filter_by(project_id=project_id).order_by(ScopeSnapshot.id.desc()).all()
    return [serialize_snapshot(row) for row in rows]
