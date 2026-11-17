from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import Project, Authorization, Target, AuditEvent, User
from app.schemas.control_plane import (
    ProjectCreate, ProjectRead, AuthorizationCreate, AuthorizationRead,
    TargetCreate, TargetRead, AuditRead,
)

router = APIRouter(prefix="/api/v1")

def audit(db: Session, actor: User, action: str, resource_type: str, resource_id: int, details: str = ""):
    db.add(AuditEvent(actor_user_id=actor.id, action=action, resource_type=resource_type,
                      resource_id=str(resource_id), details=details))

def owned_project(db: Session, project_id: int, actor: User) -> Project:
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@router.post("/projects", response_model=ProjectRead, status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    project = Project(owner_id=actor.id, name=payload.name, description=payload.description)
    db.add(project)
    db.flush()
    audit(db, actor, "project.created", "project", project.id, project.name)
    db.commit()
    db.refresh(project)
    return project

@router.get("/projects", response_model=list[ProjectRead])
def list_projects(db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    return db.query(Project).filter_by(owner_id=actor.id).order_by(Project.id.desc()).all()

@router.post("/projects/{project_id}/authorizations", response_model=AuthorizationRead, status_code=201)
def add_authorization(project_id: int, payload: AuthorizationCreate, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    owned_project(db, project_id, actor)
    record = Authorization(project_id=project_id, reference=payload.reference,
        starts_at=payload.starts_at, expires_at=payload.expires_at, notes=payload.notes, status="pending")
    db.add(record)
    db.flush()
    audit(db, actor, "authorization.recorded", "authorization", record.id,
          "Pending review; this record does not authorize scanning by itself.")
    db.commit()
    db.refresh(record)
    return record

@router.get("/projects/{project_id}/authorizations", response_model=list[AuthorizationRead])
def list_authorizations(project_id: int, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    owned_project(db, project_id, actor)
    return db.query(Authorization).filter_by(project_id=project_id).order_by(Authorization.id.desc()).all()

@router.post("/projects/{project_id}/targets", response_model=TargetRead, status_code=201)
def add_target(project_id: int, payload: TargetCreate, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    owned_project(db, project_id, actor)
    target = Target(project_id=project_id, value=payload.value, target_type=payload.target_type)
    db.add(target)
    db.flush()
    audit(db, actor, "target.registered", "target", target.id,
          "Stored only; no network request or scan was performed.")
    db.commit()
    db.refresh(target)
    return target

@router.get("/projects/{project_id}/targets", response_model=list[TargetRead])
def list_targets(project_id: int, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    owned_project(db, project_id, actor)
    return db.query(Target).filter_by(project_id=project_id).order_by(Target.id.desc()).all()

@router.get("/audit", response_model=list[AuditRead])
def list_audit(limit: int = 100, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    safe_limit = min(max(limit, 1), 500)
    return db.query(AuditEvent).filter_by(actor_user_id=actor.id).order_by(AuditEvent.id.desc()).limit(safe_limit).all()
