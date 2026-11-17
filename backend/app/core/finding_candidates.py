"""Owner-scoped immutable persistence for unconfirmed finding candidates."""
import hashlib
import json
from sqlalchemy.orm import Session
from app.db.models import AIAnalysisRun, AuditEvent, FindingCandidateRecord, Project, User
from app.schemas.finding_candidates import FindingCandidateCreate


def _canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def persist_finding_candidate(db: Session, *, analysis_run_id: int, actor: User, payload: FindingCandidateCreate):
    run = db.query(AIAnalysisRun).join(Project, Project.id == AIAnalysisRun.project_id).filter(
        AIAnalysisRun.id == analysis_run_id, Project.owner_id == actor.id
    ).first()
    if run is None:
        raise LookupError("analysis run not found")
    qualification, bundle = payload.qualification, payload.evidence_bundle
    if qualification.qualification != "human_review_candidate":
        raise ValueError("only human-review candidates can be persisted")
    if qualification.finding_status != "unconfirmed" or qualification.execution_enabled:
        raise ValueError("candidate must remain unconfirmed and non-executable")
    if bundle.analysis_context_sha256 != run.context_sha256:
        raise ValueError("evidence bundle context does not match analysis run")
    bundle_json = _canonical_json(bundle.model_dump(mode="json"))
    bundle_digest = hashlib.sha256(bundle_json.encode("utf-8")).hexdigest()
    evidence_ids = {str(item.evidence_id) for item in bundle.items}
    observation_ids = {str(value) for item in bundle.items for value in item.observation_ids}
    if set(qualification.evidence_ids) != evidence_ids:
        raise ValueError("qualification evidence IDs do not match bundle")
    if set(qualification.observation_ids) != observation_ids:
        raise ValueError("qualification observation IDs do not match bundle")
    existing = db.query(FindingCandidateRecord).filter_by(
        analysis_run_id=run.id, candidate_fingerprint=qualification.candidate_fingerprint
    ).first()
    if existing:
        if existing.evidence_bundle_sha256 != bundle_digest:
            raise ValueError("candidate fingerprint already exists with different evidence")
        return existing
    record = FindingCandidateRecord(
        analysis_run_id=run.id, project_id=run.project_id, created_by=actor.id,
        candidate_fingerprint=qualification.candidate_fingerprint,
        qualification=qualification.qualification, finding_status="unconfirmed",
        evidence_bundle_sha256=bundle_digest, evidence_bundle_json=bundle_json,
        qualification_json=_canonical_json(qualification.model_dump(mode="json")),
        execution_enabled=False,
    )
    db.add(record)
    db.flush()
    db.add(AuditEvent(
        actor_user_id=actor.id, action="finding_candidate.persisted",
        resource_type="finding_candidate", resource_id=str(record.id),
        details=f"analysis_run_id={run.id};fingerprint={record.candidate_fingerprint};bundle_sha256={bundle_digest}",
    ))
    db.flush()
    return record


def list_finding_candidates(db: Session, *, analysis_run_id: int, actor: User):
    owned = db.query(AIAnalysisRun.id).join(Project, Project.id == AIAnalysisRun.project_id).filter(
        AIAnalysisRun.id == analysis_run_id, Project.owner_id == actor.id
    ).first()
    if owned is None:
        raise LookupError("analysis run not found")
    return db.query(FindingCandidateRecord).filter_by(
        analysis_run_id=analysis_run_id
    ).order_by(FindingCandidateRecord.id.asc()).all()
