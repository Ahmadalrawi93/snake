"""Explicit end-to-end analysis and candidate qualification orchestration."""
import hashlib
import json
from dataclasses import dataclass
from sqlalchemy.orm import Session
from app.core.deepseek_analysis import AnalysisExecutionResult, analyze_observations_with_metadata
from app.core.analysis_provenance import (build_persisted_analysis_input, bind_analysis_run_provenance, load_verified_analysis_run_context)
from app.core.analysis_persistence import persist_analysis_execution
from app.core.validation_evidence import assess_validation_evidence
from app.core.evidence_coverage import assess_evidence_coverage
from app.core.finding_qualification import qualify_finding_candidate
from app.core.finding_candidates import persist_finding_candidate
from app.db.models import AIAnalysisRun, FindingCandidateRecord, Project, User
from app.schemas.analysis_context import AnalysisContext
from app.schemas.evidence_correlation import CorrelationReport
from app.schemas.validation_evidence import ValidationEvidenceAssessment, ValidationEvidenceBundle
from app.schemas.evidence_coverage import EvidenceCoverageAssessment
from app.schemas.validation_strategy import ValidationStrategyPlan
from app.schemas.finding_candidates import FindingCandidateCreate
from app.schemas.finding_qualification import FindingQualification


@dataclass(frozen=True)
class AnalysisPipelineResult:
    execution: AnalysisExecutionResult
    analysis_run: AIAnalysisRun


@dataclass(frozen=True)
class CandidatePipelineResult:
    assessment: ValidationEvidenceAssessment
    evidence_coverage: EvidenceCoverageAssessment
    qualification: FindingQualification
    candidate: FindingCandidateRecord | None


def _digest(value: dict) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def execute_analysis_pipeline(
    db: Session, *, project_id: int, target_id: int | None, actor: User,
    context: AnalysisContext, correlations: CorrelationReport,
    api_key: str, model: str, feedback_profile=None, transport=None,
) -> AnalysisPipelineResult:
    """Explicit invocation only. Checks ownership before contacting DeepSeek."""
    project = db.query(Project).filter_by(id=project_id, owner_id=actor.id).first()
    if project is None:
        raise LookupError("project not found")
    if target_id is not None:
        from app.db.models import Target
        if db.query(Target.id).filter_by(id=target_id, project_id=project_id).first() is None:
            raise LookupError("target not found")
    execution = analyze_observations_with_metadata(
        context, correlations, api_key=api_key, model=model, transport=transport,
        feedback_profile=feedback_profile,
        feedback_project_id=project_id if feedback_profile is not None else None,
        feedback_target_id=target_id if feedback_profile is not None else None,
    )
    run = persist_analysis_execution(
        db, project_id=project_id, target_id=target_id, actor=actor,
        context=context, correlations=correlations, execution=execution,
    )
    return AnalysisPipelineResult(execution=execution, analysis_run=run)


def qualify_and_persist_candidate(
    db: Session, *, analysis_run_id: int, strategy_id: str, actor: User,
    context: AnalysisContext, bundle: ValidationEvidenceBundle,
) -> CandidatePipelineResult:
    """Recompute assessment and qualification; never trust client summaries."""
    run = db.query(AIAnalysisRun).join(Project, Project.id == AIAnalysisRun.project_id).filter(
        AIAnalysisRun.id == analysis_run_id, Project.owner_id == actor.id
    ).first()
    if run is None:
        raise LookupError("analysis run not found")
    if _digest(context.model_dump(mode="json")) != run.context_sha256:
        raise ValueError("supplied analysis context does not match persisted run digest")
    if run.provenance_sha256 is None or run.source_observation_count < 1 or run.target_id is None:
        raise ValueError("analysis run lacks verified worker observation provenance")
    verified_context, _verified_correlations = load_verified_analysis_run_context(db, run=run)
    context = verified_context
    result = json.loads(run.result_json)
    raw_plan = result.get("validation_strategy")
    if not isinstance(raw_plan, dict):
        raise ValueError("analysis run has no persisted validation strategy")
    plan = ValidationStrategyPlan.model_validate(raw_plan)
    strategy = next((item for item in plan.items if item.strategy_id == strategy_id), None)
    if strategy is None:
        raise LookupError("validation strategy not found in analysis run")
    assessment = assess_validation_evidence(
        context, strategy, bundle, expected_context_sha256=run.context_sha256,
    )
    prior = [
        row.candidate_fingerprint
        for row in db.query(FindingCandidateRecord).filter(
            FindingCandidateRecord.project_id == run.project_id,
            FindingCandidateRecord.analysis_run_id != run.id,
        ).all()
    ]
    qualification = qualify_finding_candidate(
        strategy, bundle, assessment, prior_candidate_fingerprints=prior,
    )
    evidence_coverage = assess_evidence_coverage(bundle, assessment)
    candidate = None
    if qualification.qualification == "human_review_candidate":
        candidate = persist_finding_candidate(
            db, analysis_run_id=run.id, actor=actor,
            payload=FindingCandidateCreate(qualification=qualification, evidence_bundle=bundle),
        )
    return CandidatePipelineResult(assessment, evidence_coverage, qualification, candidate)



def execute_persisted_observation_analysis(
    db: Session, *, project_id: int, target_id: int, actor: User,
    api_key: str, model: str, feedback_profile=None, transport=None,
) -> AnalysisPipelineResult:
    """Run AI only on signature-verified observations loaded from the owned target.

    This is the provenance-safe entry point. The caller owns transaction commit.
    """
    source = build_persisted_analysis_input(
        db, project_id=project_id, target_id=target_id, actor=actor,
    )
    result = execute_analysis_pipeline(
        db, project_id=project_id, target_id=target_id, actor=actor,
        context=source.context, correlations=source.correlations,
        api_key=api_key, model=model, feedback_profile=feedback_profile,
        transport=transport,
    )
    bind_analysis_run_provenance(
        db, run=result.analysis_run, project_id=project_id,
        target_id=target_id, source=source,
    )
    db.flush()
    return result
