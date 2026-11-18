"""Project-scoped comparison of integrity-checked persisted candidates; no automatic mutation."""
import hashlib
import json

from sqlalchemy.orm import Session

from app.db.models import AIAnalysisRun, FindingCandidateRecord, Project, User
from app.schemas.finding_intelligence import CandidateSimilarityInput
from app.schemas.finding_qualification import FindingQualification
from app.schemas.validation_evidence import ValidationEvidenceBundle
from app.core.finding_intelligence import compare_candidate_set


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _candidate_input(db: Session, record: FindingCandidateRecord) -> CandidateSimilarityInput:
    qualification = FindingQualification.model_validate_json(record.qualification_json)
    bundle = ValidationEvidenceBundle.model_validate_json(record.evidence_bundle_json)
    raw_bundle = json.loads(record.evidence_bundle_json)
    digest = hashlib.sha256(_canonical(raw_bundle).encode("utf-8")).hexdigest()
    run = db.query(AIAnalysisRun).filter_by(
        id=record.analysis_run_id, project_id=record.project_id
    ).first()
    evidence_ids = {str(item.evidence_id) for item in bundle.items}
    observation_ids = {
        str(value) for item in bundle.items for value in item.observation_ids
    }
    if (
        run is None
        or digest != record.evidence_bundle_sha256
        or bundle.analysis_context_sha256 != run.context_sha256
        or qualification.candidate_fingerprint != record.candidate_fingerprint
        or qualification.qualification != record.qualification
        or qualification.finding_status != record.finding_status
        or qualification.execution_enabled != record.execution_enabled
        or set(qualification.evidence_ids) != evidence_ids
        or set(qualification.observation_ids) != observation_ids
    ):
        raise ValueError("candidate integrity check failed during similarity comparison")
    evidence_texts = [
        " ".join(filter(None, (item.statement, item.source_label)))
        for item in bundle.items
    ]
    return CandidateSimilarityInput(
        candidate_fingerprint=record.candidate_fingerprint,
        category=qualification.category,
        title=qualification.title,
        observation_ids=qualification.observation_ids,
        evidence_texts=evidence_texts,
    )


def compare_persisted_candidate(db: Session, *, project_id: int, candidate_id: int, actor: User):
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise LookupError("project not found")
    current = db.query(FindingCandidateRecord).filter_by(
        id=candidate_id, project_id=project_id,
    ).first()
    if current is None:
        raise LookupError("candidate not found")
    candidate = _candidate_input(db, current)
    records = db.query(FindingCandidateRecord).filter(
        FindingCandidateRecord.project_id == project_id,
        FindingCandidateRecord.id != candidate_id,
    ).order_by(FindingCandidateRecord.candidate_fingerprint.asc()).all()
    return compare_candidate_set(candidate, [_candidate_input(db, record) for record in records])
