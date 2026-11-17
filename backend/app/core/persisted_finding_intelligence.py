"""Project-scoped comparison of persisted candidates; no automatic mutation."""
import json
from sqlalchemy.orm import Session
from app.db.models import FindingCandidateRecord, Project, User
from app.schemas.finding_intelligence import CandidateSimilarityInput
from app.core.finding_intelligence import compare_candidate_set


def compare_persisted_candidate(db: Session, *, project_id: int, candidate_id: int, actor: User):
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise LookupError("project not found")
    current = db.query(FindingCandidateRecord).filter_by(
        id=candidate_id, project_id=project_id
    ).first()
    if current is None:
        raise LookupError("candidate not found")
    current_data = json.loads(current.qualification_json)
    candidate = CandidateSimilarityInput(
        candidate_fingerprint=current.candidate_fingerprint,
        category=current_data["category"],
        title=current_data["title"],
        observation_ids=current_data["observation_ids"],
    )
    records = db.query(FindingCandidateRecord).filter(
        FindingCandidateRecord.project_id == project_id,
        FindingCandidateRecord.id != candidate_id,
    ).order_by(FindingCandidateRecord.candidate_fingerprint.asc()).all()
    prior = []
    for record in records:
        data = json.loads(record.qualification_json)
        prior.append(CandidateSimilarityInput(
            candidate_fingerprint=record.candidate_fingerprint,
            category=data["category"], title=data["title"],
            observation_ids=data["observation_ids"],
        ))
    return compare_candidate_set(candidate, prior)
