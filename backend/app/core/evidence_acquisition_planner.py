"""Turn verified evidence gaps into a deterministic, manual-only collection plan."""
import hashlib

from app.schemas.evidence_gap_intelligence import EvidenceGapReport
from app.schemas.evidence_acquisition_plan import EvidenceAcquisitionPlan, EvidenceAcquisitionStep
from app.schemas.validation_evidence import ValidationEvidenceBundle
from app.schemas.validation_strategy import ValidationStrategyItem


# Priority encodes documentary dependency order, not vulnerability severity.
_RULES = {
    "program_policy": (0, "critical", "retrieve_existing_record",
        ["Official program policy", "Written authorization from the program owner"],
        "Use the official program policy or written owner permission. Asset discovery alone is not authorization.",
        "Confirm current scope and permitted methods before any testing is considered."),
    "expected_behavior": (1, "critical", "request_official_clarification",
        ["Official product documentation", "Written program-owner clarification"],
        "Obtain the intended access-control or workflow rule from an authoritative source; do not infer it from observed behavior.",
        "No production probing to discover intended behavior."),
    "authorized_test_account": (2, "critical", "request_designated_test_context",
        ["Program-provided test accounts", "Written approval identifying test identities and objects"],
        "Request explicitly designated test identities and test objects through the program's approved channel.",
        "Never use real-user accounts, third-party data, guessed credentials, or accounts not explicitly approved."),
    "observed_behavior": (3, "high", "review_existing_evidence",
        ["Existing authorized test records", "Previously captured in-scope observations"],
        "Review only existing records produced within written scope and designated test context; document provenance.",
        "Do not generate requests, payloads, commands, or new tests."),
    "impact_context": (4, "high", "retrieve_existing_record",
        ["Approved test artifacts", "Program-owner confirmation", "Existing source-linked records"],
        "Document impact only from approved artifacts or owner confirmation, and distinguish demonstrated effect from inferred consequence.",
        "No irreversible changes, real-user data access, or out-of-scope evidence collection."),
    "source_traceability": (5, "normal", "retrieve_existing_record",
        ["Immutable observation records", "Verified analysis-run provenance"],
        "Attach original immutable observation references from the same verified analysis context.",
        "Do not guess identifiers or import evidence from another target, project, or scope."),
    "strategy_linkage": (6, "normal", "review_existing_evidence",
        ["Strategy supporting-observation references", "Evidence bundle references"],
        "Check whether the evidence references the exact observations supporting this strategy.",
        "Do not substitute observations from another hypothesis or target."),
    "contradiction_resolution": (7, "critical", "reconcile_contradictory_records",
        ["Original contradictory evidence records", "Authoritative clarification", "Reviewer decision record"],
        "Review every contradictory record and preserve its provenance; record a reasoned resolution or leave it unresolved.",
        "Never delete, suppress, or relabel contradictory evidence merely to improve readiness."),
}


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]


def build_evidence_acquisition_plan(
    strategy: ValidationStrategyItem,
    bundle: ValidationEvidenceBundle,
    report: EvidenceGapReport,
) -> EvidenceAcquisitionPlan:
    """Build manual next steps from gaps, validating every referenced source ID."""
    if strategy.strategy_id != bundle.strategy_id or strategy.strategy_id != report.strategy_id:
        raise ValueError("strategy, evidence bundle, and gap report must match")
    if report.gap_count != len(report.gaps):
        raise ValueError("gap report count does not match its contents")
    if report.hard_blocker_count != sum(g.hard_blocker for g in report.gaps):
        raise ValueError("gap report hard blocker count does not match its contents")

    valid_evidence = {str(item.evidence_id) for item in bundle.items}
    valid_observations = {str(ref) for item in bundle.items for ref in item.observation_ids}
    seen_gap_ids: set[str] = set()
    ordered = []
    for gap in report.gaps:
        if gap.gap_id in seen_gap_ids:
            raise ValueError("duplicate gap ID in report")
        seen_gap_ids.add(gap.gap_id)
        if gap.category not in _RULES:
            raise ValueError("unsupported evidence gap category")
        if not set(gap.related_evidence_ids) <= valid_evidence:
            raise ValueError("gap references evidence outside the supplied bundle")
        if not set(gap.related_observation_ids) <= valid_observations:
            raise ValueError("gap references observations outside the supplied bundle")
        ordered.append(gap)

    ordered.sort(key=lambda g: (_RULES[g.category][0], g.category, g.gap_id))
    steps = []
    previous_critical: list[str] = []
    for gap in ordered:
        rank, priority, action, sources, objective, boundary = _RULES[gap.category]
        # Only explicit policy prerequisites gate later acquisition tasks.
        dependencies = list(previous_critical) if rank > 0 and previous_critical else []
        step_id = _digest(strategy.strategy_id, gap.gap_id, action)
        prerequisites = [
            "Human reviewer retains the original evidence and provenance.",
            "Any requested material must relate to this strategy and the same authorized target.",
        ]
        if gap.category != "program_policy":
            prerequisites.insert(0, "Written program authorization and current scope must be confirmed before any testing.")
        steps.append(EvidenceAcquisitionStep(
            step_id=step_id, gap_id=gap.gap_id, category=gap.category,
            priority=priority, action_kind=action, objective=objective,
            acceptable_sources=sources, prerequisites=prerequisites,
            depends_on_step_ids=dependencies, safe_boundary=boundary,
        ))
        if gap.category == "program_policy":
            previous_critical.append(step_id)

    plan_id = _digest(strategy.strategy_id, *[step.step_id for step in steps])
    return EvidenceAcquisitionPlan(
        strategy_id=strategy.strategy_id, plan_id=plan_id, steps=steps,
        step_count=len(steps),
        unresolved_hard_blocker_count=report.hard_blocker_count,
    )
