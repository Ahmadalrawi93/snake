"""Prioritize evidence-backed manual validation questions without generating test commands."""
from collections import OrderedDict
from uuid import UUID

from app.schemas.analysis_context import AnalysisContext
from app.schemas.business_logic import BusinessLogicProfile
from app.schemas.cross_surface import CrossSurfaceProfile
from app.schemas.observation_triage import ObservationTriage
from app.schemas.validation_strategy import ValidationStrategyItem, ValidationStrategyPlan


_CATEGORY_MAP = {
    "authentication": "authentication_boundary",
    "authorization": "object_authorization",
    "information_exposure": "information_exposure",
    "injection": "injection",
    "security_misconfiguration": "configuration_review",
    "business_logic": "workflow_integrity",
    "other": "general_review",
}


def _available_ids(context: AnalysisContext) -> set[str]:
    values = [
        value
        for group in context.groups for item in group.observations
        for value in item.observation_ids
    ] + [
        value for item in context.ungrouped for value in item.observation_ids
    ]
    # Normalize UUIDs and reject malformed provenance values.
    return {str(UUID(value)) for value in values}


def build_validation_strategy(
    context: AnalysisContext,
    triage: ObservationTriage,
    business: BusinessLogicProfile,
    cross_surface: CrossSurfaceProfile,
    *,
    max_items: int = 100,
) -> ValidationStrategyPlan:
    """Build a deterministic, manual-only plan from evidence already in the context."""
    if not 1 <= max_items <= 500:
        raise ValueError("invalid validation strategy limit")
    available = _available_ids(context)
    triage_ids = {str(value) for value in triage.supporting_observation_ids}
    if not triage_ids or not triage_ids.issubset(available):
        raise ValueError("triage evidence is not contained in analysis context")

    drafts: OrderedDict[str, dict] = OrderedDict()

    def add(key: str, category: str, priority: str, basis: str, hypothesis: str,
            ids: set[str], missing: list[str], questions: list[str],
            actions: list[str], prerequisites: list[str]) -> None:
        normalized = {str(UUID(value)) for value in ids}
        if not normalized or not normalized.issubset(available):
            raise ValueError("strategy evidence is not contained in analysis context")
        existing = drafts.get(key)
        if existing:
            existing["supporting_observation_ids"] = sorted(
                set(existing["supporting_observation_ids"]) | normalized
            )[:500]
            return
        drafts[key] = dict(
            strategy_id=key, category=category, priority=priority,
            priority_basis=basis, hypothesis=hypothesis,
            supporting_observation_ids=sorted(normalized)[:500],
            missing_evidence=missing[:20], validation_questions=questions[:12],
            manual_review_actions=actions[:8], prerequisites=prerequisites[:8],
        )

    triage_category = _CATEGORY_MAP[triage.category]
    triage_priority = "medium" if triage.confidence == "high" else "low"
    if triage.confidence == "medium":
        triage_priority = "medium"
    add(
        f"triage_{triage.category}", triage_category, triage_priority,
        "Priority reflects model confidence only; it is not vulnerability severity or proof.",
        triage.hypothesis, triage_ids, list(triage.missing_evidence),
        list(triage.validation_questions),
        ["Compare the hypothesis against the original observations and program policy.",
         "Have a human reviewer record the evidence needed to accept or reject the hypothesis."],
        ["Confirm current written program authorization and target scope before any testing.",
         "Use only designated test accounts and data supplied or approved for the program."],
    )

    for hypothesis in business.hypotheses:
        ids = set(hypothesis.supporting_observation_ids)
        if hypothesis.category == "object_authorization":
            add(
                "business_object_authorization", "object_authorization", "high",
                "Paired collection and identifier-shaped routes were observed; no access-control behavior is known.",
                hypothesis.statement, ids,
                ["Documented ownership model", "Expected access rules for each test role",
                 "Observed allow/deny behavior from authorized test identities"],
                list(hypothesis.validation_questions),
                ["Review access rules with the program's documented test identities.",
                 "Compare only objects and accounts explicitly provisioned for testing."],
                ["Written scope must include the relevant host and application area.",
                 "Use two authorized test identities with program-provided test objects."],
            )
        elif hypothesis.category == "sensitive_action":
            add(
                "business_sensitive_action", "sensitive_action_authorization", "medium",
                "A route name resembles a sensitive operation; its method and behavior remain unknown.",
                hypothesis.statement, ids,
                ["Actual operation semantics", "Required role and ownership rules",
                 "Expected state transition and audit behavior"],
                list(hypothesis.validation_questions),
                ["Confirm operation semantics from documentation or the program owner.",
                 "Review authorization and state-transition requirements without changing real data."],
                ["Written scope must cover the operation.",
                 "Use a non-production or explicitly designated test object."],
            )

    for link in cross_surface.links:
        ids = set(link.observation_ids)
        if link.relation == "authentication_to_object_surface":
            key, category = "cross_auth_object", "object_authorization"
            priority = "high"
            actions = ["Map the documented authentication boundary to the object authorization policy.",
                       "Review whether object-level checks are independently applied."]
        elif link.relation == "authentication_to_sensitive_action":
            key, category = "cross_auth_sensitive_action", "sensitive_action_authorization"
            priority = "medium"
            actions = ["Confirm the documented role allowed to perform the operation.",
                       "Review server-side authorization and state checks for the operation."]
        else:
            key, category = "cross_object_sensitive_action", "workflow_integrity"
            priority = "medium"
            actions = ["Compare documented object ownership rules with operation permissions.",
                       "Review allowed state transitions and replay protections."]
        add(
            key, category, priority,
            "Related route families were co-observed on one host; shared controls and behavior are unverified.",
            link.rationale, ids,
            ["Endpoint-to-control mapping", "Expected role and ownership matrix",
             "Observed behavior using only approved test identities"],
            list(link.validation_questions), actions,
            ["Verify current authorization and exact target scope.",
             "Do not test against real user data or perform irreversible state changes."],
        )

    items = [
        ValidationStrategyItem(**draft)
        for draft in drafts.values()
    ]
    priority_order = {"high": 0, "medium": 1, "low": 2}
    items.sort(key=lambda item: (priority_order[item.priority], item.strategy_id))
    return ValidationStrategyPlan(
        items=items[:max_items],
        global_prerequisites=[
            "A current, approved authorization record and immutable scope snapshot must be verified by the backend before testing.",
            "A human must review each proposed validation question and confirm it is within the written authorization and permitted by the program.",
            "Any active request, state change, or use of credentials requires a separate authorization-approved execution workflow; this plan does not authorize it.",
        ],
    )
