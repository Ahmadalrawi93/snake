"""Owner-scoped append-only finding lifecycle and encrypted evidence vault."""
import base64
import hashlib
import os
import re
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session
from app.core.analysis_redaction import redact_text
from app.db.models import (
    AuditEvent, EvidenceArtifact, FindingCandidateRecord, FindingLifecycleEvent,
    Project, User,
)
from app.schemas.finding_lifecycle import EvidenceArtifactCreate, FindingLifecycleCreate

_ALLOWED_TRANSITIONS = {
    "new": {"under_review"},
    "under_review": {"needs_more_evidence", "confirmed", "rejected", "duplicate"},
    "needs_more_evidence": {"under_review", "rejected"},
    "confirmed": set(),
    "rejected": set(),
    "duplicate": set(),
}


def _fernet() -> Fernet:
    key = os.environ.get("SNAKE_EVIDENCE_VAULT_FERNET_KEY", "")
    if not key:
        raise RuntimeError("Evidence vault encryption key is not configured")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("Evidence vault encryption key is invalid") from exc


def _owned_candidate(db: Session, candidate_id: int, actor: User):
    row = db.query(FindingCandidateRecord).join(
        Project, Project.id == FindingCandidateRecord.project_id
    ).filter(
        FindingCandidateRecord.id == candidate_id,
        Project.owner_id == actor.id,
    ).first()
    if row is None:
        raise LookupError("candidate not found")
    return row


def current_finding_status(db: Session, candidate_id: int) -> str:
    event = db.query(FindingLifecycleEvent).filter_by(
        candidate_id=candidate_id
    ).order_by(FindingLifecycleEvent.id.desc()).first()
    return event.to_status if event else "new"


def append_lifecycle_event(
    db: Session, *, candidate_id: int, actor: User, payload: FindingLifecycleCreate
):
    candidate = _owned_candidate(db, candidate_id, actor)
    current = current_finding_status(db, candidate.id)
    if payload.expected_status != current:
        raise ValueError("stale lifecycle state")
    if payload.new_status not in _ALLOWED_TRANSITIONS[current]:
        raise ValueError("transition is not allowed")
    if payload.new_status == "duplicate":
        if not payload.related_candidate_fingerprint or payload.related_candidate_fingerprint == candidate.candidate_fingerprint:
            raise ValueError("duplicate status requires a different related candidate")
        related = db.query(FindingCandidateRecord.id).filter_by(
            project_id=candidate.project_id,
            candidate_fingerprint=payload.related_candidate_fingerprint,
        ).first()
        if related is None:
            raise ValueError("related candidate does not exist in this project")
    elif payload.related_candidate_fingerprint is not None:
        raise ValueError("related candidate is only valid for duplicate status")

    record = FindingLifecycleEvent(
        candidate_id=candidate.id, project_id=candidate.project_id,
        actor_id=actor.id, from_status=current, to_status=payload.new_status,
        rationale=redact_text(payload.rationale),
        related_candidate_fingerprint=payload.related_candidate_fingerprint,
    )
    db.add(record)
    db.flush()
    db.add(AuditEvent(
        actor_user_id=actor.id, action="finding_lifecycle.transitioned",
        resource_type="finding_candidate", resource_id=str(candidate.id),
        details=f"from={current};to={payload.new_status};event_id={record.id}",
    ))
    db.flush()
    return record


def store_evidence_artifact(
    db: Session, *, candidate_id: int, actor: User, payload: EvidenceArtifactCreate
):
    candidate = _owned_candidate(db, candidate_id, actor)
    # Bound decoded bytes to 1 MiB and reject malformed/non-canonical Base64.
    try:
        raw = base64.b64decode(payload.content_base64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("evidence content is not valid base64") from exc
    if not raw or len(raw) > 1024 * 1024:
        raise ValueError("evidence must be between 1 byte and 1 MiB")
    # Strip path components; only a display filename is retained.
    filename = re.split(r"[/\\\\]", payload.filename)[-1].strip().replace(chr(34), "_")
    if not filename or filename in {".", ".."}:
        raise ValueError("invalid evidence filename")
    encrypted = _fernet().encrypt(raw)
    digest = hashlib.sha256(raw).hexdigest()
    record = EvidenceArtifact(
        candidate_id=candidate.id, project_id=candidate.project_id,
        uploaded_by=actor.id, filename=filename, media_type=payload.media_type,
        content_sha256=digest, size_bytes=len(raw), encrypted_content=encrypted,
        description=redact_text(payload.description),
    )
    db.add(record)
    db.flush()
    db.add(AuditEvent(
        actor_user_id=actor.id, action="finding_evidence.uploaded",
        resource_type="finding_evidence", resource_id=str(record.id),
        details=f"candidate_id={candidate.id};sha256={digest};bytes={len(raw)}",
    ))
    db.flush()
    return record


def read_evidence_artifact(db: Session, *, artifact_id: int, actor: User):
    row = db.query(EvidenceArtifact).join(
        Project, Project.id == EvidenceArtifact.project_id
    ).filter(
        EvidenceArtifact.id == artifact_id,
        Project.owner_id == actor.id,
    ).first()
    if row is None:
        raise LookupError("evidence artifact not found")
    try:
        raw = _fernet().decrypt(row.encrypted_content)
    except InvalidToken as exc:
        raise RuntimeError("Evidence integrity/decryption check failed") from exc
    if hashlib.sha256(raw).hexdigest() != row.content_sha256 or len(raw) != row.size_bytes:
        raise RuntimeError("Evidence integrity check failed")
    return row, raw
