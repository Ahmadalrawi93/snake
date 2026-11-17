"""Project-scoped comparison of persisted candidates; no automatic mutation."""
import json
from sqlalchemy.orm import Session
from app.db.models import FindingCandidateRecord, Project, User
from app.schemas.finding_intelligence import CandidateSimilarityInput
from app.core.finding_intelligence import compare_candidate_set


def _candidate_input(record: FindingCandidateRecord) -> CandidateSimilarityInput:
    qualification = json.loads(record.qualification_json)
    bundle = json.loads(record.evidence_bundle_json)
    evidence_texts = [
        " ".join(filter(None, (item.get("statement", ""), item.get("source_label", ""))))
        for item in bundle.get("items", [])
    ]
    return CandidateSimilarityInput(
        candidate_fingerprint=record.candidate_fingerprint,
        category=qualification["category"],
        title=qualification["title"],
        observation_ids=qualification["observation_ids"],
        evidence_texts=evidence_texts,
    )


def compare_persisted_candidate(db: Session, *, project_id: int, candidate_id: int, actor: User):
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise LookupError("project not found")
    current = db.query(FindingCandidateRecord).filter_by(
        id=candidate_id, project_id=project_id
    ).first()
    if current is None:
        raise LookupError("candidate not found")
    candidate = _candidate_input(current)
    records = db.query(FindingCandidateRecord).filter(
        FindingCandidateRecord.project_id == project_id,
        FindingCandidateRecord.id != candidate_id,
    ).order_by(FindingCandidateRecord.candidate_fingerprint.asc()).all()
    return compare_candidate_set(candidate, [_candidate_input(record) for record in records])
