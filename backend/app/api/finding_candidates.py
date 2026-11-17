"""Owner-scoped candidate detail, listing, and similarity APIs."""
import hashlib
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import FindingCandidateRecord, Project, User
from app.schemas.finding_qualification import FindingQualification
from app.schemas.validation_evidence import ValidationEvidenceBundle
from app.core.finding_candidates import list_finding_candidates
from app.core.persisted_finding_intelligence import compare_persisted_candidate
from app.schemas.finding_candidates import FindingCandidateRead
from app.schemas.finding_intelligence import CandidateSimilarityResult

router = APIRouter(prefix="/api/v1")


@router.get(
    "/analysis-runs/{analysis_run_id}/finding-candidates",
    response_model=list[FindingCandidateRead],
)
def read_finding_candidates(
    analysis_run_id: int, db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        return list_finding_candidates(db, analysis_run_id=analysis_run_id, actor=actor)
    except LookupError:
        raise HTTPException(status_code=404, detail="Analysis run not found")


@router.get("/finding-candidates/{candidate_id}")
def read_finding_candidate_detail(
    candidate_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    """Return validated, immutable qualification and evidence for an owned candidate."""
    candidate = (
        db.query(FindingCandidateRecord)
        .join(Project, Project.id == FindingCandidateRecord.project_id)
        .filter(
            FindingCandidateRecord.id == candidate_id,
            Project.owner_id == actor.id,
        )
        .first()
    )
    if candidate is None:
        raise HTTPException(status_code=404, detail="Candidate not found")
    try:
        qualification = FindingQualification.model_validate_json(candidate.qualification_json)
        bundle = ValidationEvidenceBundle.model_validate_json(candidate.evidence_bundle_json)
        canonical_bundle = json.dumps(
            json.loads(candidate.evidence_bundle_json),
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        digest = hashlib.sha256(canonical_bundle.encode("utf-8")).hexdigest()
        if digest != candidate.evidence_bundle_sha256:
            raise ValueError("evidence bundle digest mismatch")
        if (
            qualification.candidate_fingerprint != candidate.candidate_fingerprint
            or qualification.qualification != candidate.qualification
            or qualification.finding_status != candidate.finding_status
            or qualification.execution_enabled != candidate.execution_enabled
        ):
            raise ValueError("candidate qualification binding mismatch")
        return {
            "id": candidate.id,
            "analysis_run_id": candidate.analysis_run_id,
            "project_id": candidate.project_id,
            "candidate_fingerprint": candidate.candidate_fingerprint,
            "qualification": qualification.model_dump(mode="json"),
            "evidence_bundle": bundle.model_dump(mode="json"),
            "evidence_bundle_sha256": candidate.evidence_bundle_sha256,
            "finding_status": candidate.finding_status,
            "execution_enabled": candidate.execution_enabled,
            "created_at": candidate.created_at,
        }
    except (ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=409, detail="Stored candidate integrity check failed")


@router.get(
    "/projects/{project_id}/finding-candidates/{candidate_id}/similarity",
    response_model=list[CandidateSimilarityResult],
)
def read_candidate_similarity(
    project_id: int, candidate_id: int, db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    try:
        return compare_persisted_candidate(
            db, project_id=project_id, candidate_id=candidate_id, actor=actor
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Project or candidate not found")
