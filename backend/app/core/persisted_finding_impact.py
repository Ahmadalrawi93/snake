"""Owner-scoped, append-only persistence for evidence-bound impact assessments."""
import hashlib
import json

from sqlalchemy.orm import Session

from app.core.analysis_provenance import load_verified_analysis_run_context
from app.core.finding_impact import assess_finding_impact
from app.core.validation_evidence import assess_validation_evidence
from app.db.models import (
    AIAnalysisRun, AuditEvent, FindingCandidateRecord,
    FindingImpactAssessmentRecord, Project, User,
)
from app.schemas.finding_impact import FindingImpactClaim, FindingImpactAssessment
from app.schemas.validation_evidence import ValidationEvidenceBundle
from app.schemas.finding_qualification import FindingQualification
from app.schemas.validation_strategy import ValidationStrategyPlan


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _serialize(record: FindingImpactAssessmentRecord) -> dict:
    return {
        "id": record.id,
        "candidate_id": record.candidate_id,
        "analysis_run_id": record.analysis_run_id,
        "project_id": record.project_id,
        "reviewer_id": record.reviewer_id,
        "evidence_bundle_sha256": record.evidence_bundle_sha256,
        "claims_sha256": record.claims_sha256,
        "assessment_sha256": record.assessment_sha256,
        "assessment": json.loads(record.assessment_json),
        "final_severity": record.final_severity,
        "cvss_vector": record.cvss_vector,
        "execution_enabled": record.execution_enabled,
        "created_at": record.created_at,
    }


def create_persisted_finding_impact(
    db: Session, *, candidate_id: int, actor: User,
    claims: list[FindingImpactClaim],
) -> dict:
    """Rebuild evidence assessment from verified run provenance; never trust client summaries."""
    candidate = (
        db.query(FindingCandidateRecord)
        .join(AIAnalysisRun, AIAnalysisRun.id == FindingCandidateRecord.analysis_run_id)
        .join(Project, Project.id == FindingCandidateRecord.project_id)
        .filter(
            FindingCandidateRecord.id == candidate_id,
            FindingCandidateRecord.qualification == "human_review_candidate",
            FindingCandidateRecord.finding_status == "unconfirmed",
            FindingCandidateRecord.execution_enabled.is_(False),
            Project.owner_id == actor.id,
            AIAnalysisRun.project_id == FindingCandidateRecord.project_id,
        ).first()
    )
    if candidate is None:
        raise LookupError("candidate not found")
    run = db.query(AIAnalysisRun).filter_by(
        id=candidate.analysis_run_id, project_id=candidate.project_id
    ).first()
    if run is None:
        raise LookupError("analysis run not found")

    bundle_data = json.loads(candidate.evidence_bundle_json)
    bundle = ValidationEvidenceBundle.model_validate(bundle_data)
    if _sha256(_canonical(bundle_data)) != candidate.evidence_bundle_sha256:
        raise ValueError("persisted evidence bundle digest mismatch")
    qualification = FindingQualification.model_validate_json(candidate.qualification_json)
    context, _correlations = load_verified_analysis_run_context(db, run=run)
    context_data = context.model_dump(mode="json")
    if _sha256(_canonical(context_data)) != run.context_sha256:
        raise ValueError("verified analysis context digest mismatch")

    raw_result = json.loads(run.result_json)
    raw_plan = raw_result.get("validation_strategy")
    if not isinstance(raw_plan, dict):
        raise ValueError("analysis run has no persisted validation strategy")
    plan = ValidationStrategyPlan.model_validate(raw_plan)
    strategy = next(
        (item for item in plan.items if item.strategy_id == bundle.strategy_id), None
    )
    if strategy is None:
        raise ValueError("evidence strategy is not present in the analysis run")

    evidence_assessment = assess_validation_evidence(
        context, strategy, bundle, expected_context_sha256=run.context_sha256,
    )
    assessment: FindingImpactAssessment = assess_finding_impact(
        qualification, bundle, evidence_assessment, claims,
    )
    claims_json = _canonical([claim.model_dump(mode="json") for claim in claims])
    assessment_json = _canonical(assessment.model_dump(mode="json"))
    claims_digest = _sha256(claims_json)
    assessment_digest = _sha256(assessment_json)

    existing = db.query(FindingImpactAssessmentRecord).filter_by(
        candidate_id=candidate.id, assessment_sha256=assessment_digest,
    ).first()
    if existing is not None:
        return _serialize(existing)

    record = FindingImpactAssessmentRecord(
        candidate_id=candidate.id,
        analysis_run_id=run.id,
        project_id=candidate.project_id,
        reviewer_id=actor.id,
        evidence_bundle_sha256=candidate.evidence_bundle_sha256,
        claims_sha256=claims_digest,
        assessment_sha256=assessment_digest,
        assessment_json=assessment_json,
        final_severity="not_assessed",
        cvss_vector=None,
        execution_enabled=False,
    )
    db.add(record)
    db.flush()
    db.add(AuditEvent(
        actor_user_id=actor.id,
        action="finding_impact_assessment.recorded",
        resource_type="finding_impact_assessment",
        resource_id=str(record.id),
        details=(
            f"candidate_id={candidate.id};analysis_run_id={run.id};"
            f"assessment_sha256={assessment_digest};evidence_bundle_sha256={candidate.evidence_bundle_sha256}"
        ),
    ))
    db.flush()
    return _serialize(record)


def list_persisted_finding_impacts(
    db: Session, *, candidate_id: int, actor: User,
) -> list[dict]:
    candidate = (
        db.query(FindingCandidateRecord.id)
        .join(Project, Project.id == FindingCandidateRecord.project_id)
        .filter(FindingCandidateRecord.id == candidate_id, Project.owner_id == actor.id)
        .first()
    )
    if candidate is None:
        raise LookupError("candidate not found")
    records = (
        db.query(FindingImpactAssessmentRecord)
        .filter_by(candidate_id=candidate_id)
        .order_by(FindingImpactAssessmentRecord.id.asc())
        .all()
    )
    return [_serialize(record) for record in records]
