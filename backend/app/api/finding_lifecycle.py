"""Authenticated lifecycle and evidence-vault APIs."""
import base64
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.api.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.core.finding_lifecycle import (
    append_lifecycle_event, store_evidence_artifact, read_evidence_artifact,
    current_finding_status, evidence_content_disposition,
)
from app.schemas.finding_lifecycle import (
    FindingLifecycleCreate, FindingLifecycleRead, EvidenceArtifactCreate,
    EvidenceArtifactRead,
)

router = APIRouter(prefix="/api/v1")


@router.post("/finding-candidates/{candidate_id}/lifecycle", response_model=FindingLifecycleRead, status_code=201)
def transition_candidate(candidate_id: int, payload: FindingLifecycleCreate,
                          db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    try:
        row = append_lifecycle_event(db, candidate_id=candidate_id, actor=actor, payload=payload)
        db.commit()
        db.refresh(row)
        return row
    except LookupError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Candidate not found")
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))


@router.get("/finding-candidates/{candidate_id}/lifecycle")
def read_candidate_lifecycle(candidate_id: int, db: Session = Depends(get_db),
                             actor: User = Depends(get_current_user)):
    from app.core.finding_lifecycle import _owned_candidate
    try:
        candidate = _owned_candidate(db, candidate_id, actor)
    except LookupError:
        raise HTTPException(status_code=404, detail="Candidate not found")
    from app.db.models import FindingLifecycleEvent, Project
    events = db.query(FindingLifecycleEvent).join(
        Project, Project.id == FindingLifecycleEvent.project_id
    ).filter(
        FindingLifecycleEvent.candidate_id == candidate.id,
        FindingLifecycleEvent.project_id == candidate.project_id,
        Project.owner_id == actor.id,
    ).order_by(FindingLifecycleEvent.id.asc()).all()
    return {"candidate_id": candidate.id, "current_status": current_finding_status(db, candidate.id), "events": [FindingLifecycleRead.model_validate(e) for e in events]}


@router.post("/finding-candidates/{candidate_id}/evidence", response_model=EvidenceArtifactRead, status_code=201)
def upload_evidence(candidate_id: int, payload: EvidenceArtifactCreate,
                    db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    try:
        row = store_evidence_artifact(db, candidate_id=candidate_id, actor=actor, payload=payload)
        db.commit()
        db.refresh(row)
        return row
    except LookupError:
        db.rollback()
        raise HTTPException(status_code=404, detail="Candidate not found")
    except RuntimeError:
        db.rollback()
        raise HTTPException(status_code=503, detail="Evidence vault encryption is unavailable")
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/finding-candidates/{candidate_id}/evidence", response_model=list[EvidenceArtifactRead])
def list_evidence(candidate_id: int, db: Session = Depends(get_db),
                  actor: User = Depends(get_current_user)):
    from app.core.finding_lifecycle import _owned_candidate
    from app.db.models import EvidenceArtifact, Project
    try:
        candidate = _owned_candidate(db, candidate_id, actor)
    except LookupError:
        raise HTTPException(status_code=404, detail="Candidate not found")
    return db.query(EvidenceArtifact).join(
        Project, Project.id == EvidenceArtifact.project_id
    ).filter(
        EvidenceArtifact.candidate_id == candidate.id,
        EvidenceArtifact.project_id == candidate.project_id,
        Project.owner_id == actor.id,
    ).order_by(EvidenceArtifact.id.asc()).all()


@router.get("/finding-evidence/{artifact_id}/content")
def download_evidence(artifact_id: int, db: Session = Depends(get_db),
                      actor: User = Depends(get_current_user)):
    try:
        row, raw = read_evidence_artifact(db, artifact_id=artifact_id, actor=actor)
    except LookupError:
        raise HTTPException(status_code=404, detail="Evidence artifact not found")
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Evidence integrity or encryption check failed")
    db.commit()
    return Response(
        content=raw,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": evidence_content_disposition(row.filename),
            "X-Content-SHA256": row.content_sha256,
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )
