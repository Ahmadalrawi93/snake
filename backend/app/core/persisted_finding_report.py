"""Build a report draft only from revalidated, owner-scoped persisted evidence."""
import hashlib
import json

from sqlalchemy.orm import Session

from app.core.analysis_provenance import load_verified_analysis_run_context
from app.core.finding_report import build_finding_report_draft, render_finding_report_markdown
from app.core.validation_evidence import assess_validation_evidence
from app.db.models import AIAnalysisRun, FindingCandidateRecord, Project, User
from app.schemas.finding_qualification import FindingQualification
from app.schemas.finding_report import FindingReportDraft
from app.schemas.validation_evidence import ValidationEvidenceBundle
from app.schemas.validation_strategy import ValidationStrategyPlan


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_persisted_candidate_report(
    db: Session, *, candidate_id: int, actor: User
) -> tuple[FindingReportDraft, str]:
    candidate = (
        db.query(FindingCandidateRecord)
        .join(Project, Project.id == FindingCandidateRecord.project_id)
        .filter(
            FindingCandidateRecord.id == candidate_id,
            Project.owner_id == actor.id,
            FindingCandidateRecord.qualification == "human_review_candidate",
            FindingCandidateRecord.finding_status == "unconfirmed",
            FindingCandidateRecord.execution_enabled.is_(False),
        )
        .first()
    )
    if candidate is None:
        raise LookupError("candidate not found")

    run = db.query(AIAnalysisRun).filter_by(
        id=candidate.analysis_run_id, project_id=candidate.project_id
    ).first()
    if run is None:
        raise ValueError("candidate analysis run is missing")

    bundle = ValidationEvidenceBundle.model_validate_json(candidate.evidence_bundle_json)
    qualification = FindingQualification.model_validate_json(candidate.qualification_json)
    bundle_data = json.loads(candidate.evidence_bundle_json)
    digest = hashlib.sha256(_canonical(bundle_data).encode("utf-8")).hexdigest()
    evidence_ids = {str(item.evidence_id) for item in bundle.items}
    observation_ids = {
        str(value) for item in bundle.items for value in item.observation_ids
    }
    if (
        digest != candidate.evidence_bundle_sha256
        or bundle.analysis_context_sha256 != run.context_sha256
        or qualification.candidate_fingerprint != candidate.candidate_fingerprint
        or qualification.qualification != candidate.qualification
        or qualification.finding_status != candidate.finding_status
        or qualification.execution_enabled != candidate.execution_enabled
        or set(qualification.evidence_ids) != evidence_ids
        or set(qualification.observation_ids) != observation_ids
    ):
        raise ValueError("candidate evidence or qualification integrity check failed")

    context, _correlations = load_verified_analysis_run_context(db, run=run)
    if hashlib.sha256(_canonical(context.model_dump(mode="json")).encode("utf-8")).hexdigest() != run.context_sha256:
        raise ValueError("verified analysis context digest mismatch")

    result = json.loads(run.result_json)
    raw_plan = result.get("validation_strategy")
    if not isinstance(raw_plan, dict):
        raise ValueError("analysis run has no persisted validation strategy")
    plan = ValidationStrategyPlan.model_validate(raw_plan)
    strategy = next(
        (item for item in plan.items if item.strategy_id == bundle.strategy_id), None
    )
    if strategy is None:
        raise ValueError("evidence strategy is not present in the analysis run")

    assessment = assess_validation_evidence(
        context, strategy, bundle, expected_context_sha256=run.context_sha256
    )
    report = build_finding_report_draft(qualification, bundle, assessment)
    return report, render_finding_report_markdown(report)
