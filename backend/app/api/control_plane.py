from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import Project, Authorization, Target, AuditEvent
from app.schemas.control_plane import (
    ProjectCreate, ProjectRead, AuthorizationCreate, AuthorizationRead,
    TargetCreate, TargetRead, AuditRead,
)

router = APIRouter(prefix="/api/v1")

def audit(db: Session, action: str, resource_type: str, resource_id: int, details: str = ""):
    db.add(AuditEvent(action=action, resource_type=resource_type, resource_id=str(resource_id), details=details))

@router.post("/projects", response_model=ProjectRead, status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    project = Project(name=payload.name, description=payload.description)
    db.add(project)
    db.flush()
    audit(db, "project.created", "project", project.id, project.name)
    db.commit()
    db.refresh(project)
    return project

@router.get("/projects", response_model=list[ProjectRead])
def list_projects(db: Session = Depends(get_db)):
    return db.query(Project).order_by(Project.id.desc()).all()

@router.post("/projects/{project_id}/authorizations", response_model=AuthorizationRead, status_code=201)
def add_authorization(project_id: int, payload: AuthorizationCreate, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    record = Authorization(project_id=project_id, reference=payload.reference,
        starts_at=payload.starts_at, expires_at=payload.expires_at,
        notes=payload.notes, status="pending")
    db.add(record)
    db.flush()
    audit(db, "authorization.recorded", "authorization", record.id,
          "Pending review; this record does not authorize scanning by itself.")
    db.commit()
    db.refresh(record)
    return record

@router.get("/projects/{project_id}/authorizations", response_model=list[AuthorizationRead])
def list_authorizations(project_id: int, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    return db.query(Authorization).filter_by(project_id=project_id).order_by(Authorization.id.desc()).all()

@router.post("/projects/{project_id}/targets", response_model=TargetRead, status_code=201)
def add_target(project_id: int, payload: TargetCreate, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    target = Target(project_id=project_id, value=payload.value, target_type=payload.target_type)
    db.add(target)
    db.flush()
    audit(db, "target.registered", "target", target.id,
          "Stored only; no network request or scan was performed.")
    db.commit()
    db.refresh(target)
    return target

@router.get("/projects/{project_id}/targets", response_model=list[TargetRead])
def list_targets(project_id: int, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    return db.query(Target).filter_by(project_id=project_id).order_by(Target.id.desc()).all()

@router.get("/audit", response_model=list[AuditRead])
def list_audit(limit: int = 100, db: Session = Depends(get_db)):
    safe_limit = min(max(limit, 1), 500)
    return db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(safe_limit).all()
