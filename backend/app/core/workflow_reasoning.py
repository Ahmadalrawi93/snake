"""Infer possible business workflow review areas from passive routes only."""
from collections import defaultdict
from urllib.parse import urlsplit
from app.schemas.analysis_context import AnalysisContext
from app.schemas.workflow_reasoning import WorkflowActionEvidence, WorkflowReasoningReport, WorkflowTransitionHypothesis

RESOURCE_NAMES = {
    "user":"users", "users":"users", "account":"accounts", "accounts":"accounts",
    "order":"orders", "orders":"orders", "invoice":"invoices", "invoices":"invoices",
    "payment":"payments", "payments":"payments", "subscription":"subscriptions",
    "subscriptions":"subscriptions", "role":"roles", "roles":"roles",
    "document":"documents", "documents":"documents", "project":"projects", "projects":"projects",
}
ACTION_NAMES = {"create":"create", "new":"create", "add":"create", "approve":"approve",
    "reject":"reject", "refund":"refund", "transfer":"transfer", "cancel":"cancel",
    "delete":"delete", "remove":"delete", "update":"update", "edit":"update",
    "pay":"pay", "checkout":"pay", "publish":"publish", "invite":"invite", "verify":"verify"}
TRANSITION_FAMILIES = (
    ({"create"}, {"approve", "verify", "publish"}),
    ({"approve", "verify"}, {"pay", "refund", "transfer"}),
    ({"pay", "refund", "transfer"}, {"cancel", "delete"}),
    ({"update"}, {"approve", "publish"}),
)

def build_workflow_reasoning(context: AnalysisContext, *, max_hypotheses: int = 500) -> WorkflowReasoningReport:
    if not 1 <= max_hypotheses <= 1000:
        raise ValueError("invalid workflow reasoning limit")
    grouped = defaultdict(dict)
    observations = [item for group in context.groups for item in group.observations] + context.ungrouped
    for item in observations:
        if item.kind != "url":
            continue
        try:
            parsed = urlsplit(item.value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                continue
            host = (item.host_key or parsed.hostname).lower().rstrip(".")
            segments = [part.lower() for part in parsed.path.split("/") if part]
            resource = next((RESOURCE_NAMES[s] for s in segments if s in RESOURCE_NAMES), None)
            action = next((ACTION_NAMES[s] for s in segments if s in ACTION_NAMES), None)
            if not resource or not action:
                continue
            route = "/" + "/".join(segments)
            key = (host, resource, action, route)
            grouped[(host, resource)][key] = sorted(set(item.observation_ids))
        except ValueError:
            continue
    hypotheses = []
    for (host, resource), routes in sorted(grouped.items()):
        actions = sorted({key[2] for key in routes})
        if len(actions) < 2:
            continue
        evidence = [WorkflowActionEvidence(action=key[2], route_template=key[3],
            observation_ids=ids) for key, ids in sorted(routes.items())]
        pairs = []
        for left, right in TRANSITION_FAMILIES:
            for a in sorted(left.intersection(actions)):
                for b in sorted(right.intersection(actions)):
                    pairs.append(f"{a}->{b}")
        if not pairs:
            pairs = [f"{a}->{b}" for i, a in enumerate(actions) for b in actions[i+1:]][:30]
        refs = sorted({ref for item in evidence for ref in item.observation_ids})[:500]
        hypotheses.append(WorkflowTransitionHypothesis(
            host=host, resource=resource, observed_actions=actions[:12],
            action_evidence=evidence[:24], possible_transition_pairs=sorted(set(pairs))[:30],
            validation_questions=[
                "What server-side states and preconditions are required before each action?",
                "Is each transition authorized for the actor, role, and object owner?",
                "Can an action be invoked before its legitimate predecessor or after a terminal state?",
                "Are retries and duplicate transitions handled safely and consistently?",
                "Do audit records reflect the authoritative state transition?",
            ], supporting_observation_ids=refs,
        ))
    hypotheses.sort(key=lambda x: (x.host, x.resource, x.observed_actions))
    if len(hypotheses) > max_hypotheses:
        raise ValueError("workflow hypothesis limit exceeded")
    return WorkflowReasoningReport(hypotheses=hypotheses)
