"""Derive conservative business-logic test leads from already observed routes only."""
import re
from collections import defaultdict
from urllib.parse import urlsplit

from app.schemas.analysis_context import AnalysisContext
from app.schemas.business_logic import (
    BusinessActionSurface, BusinessLogicHypothesis, BusinessLogicProfile,
    BusinessObjectSurface,
)

_ID = re.compile(r"^(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})$", re.I)
_RESOURCES = {
    "user":"users", "users":"users", "account":"accounts", "accounts":"accounts",
    "order":"orders", "orders":"orders", "invoice":"invoices", "invoices":"invoices",
    "payment":"payments", "payments":"payments", "subscription":"subscriptions",
    "subscriptions":"subscriptions", "role":"roles", "roles":"roles",
    "document":"documents", "documents":"documents", "project":"projects", "projects":"projects",
}
_ACTIONS = {
    "create":"create", "new":"create", "add":"create",
    "show":"read", "view":"read", "list":"read", "get":"read",
    "edit":"update", "update":"update", "change":"update",
    "delete":"delete", "remove":"delete",
    "approve":"approve", "reject":"approve", "cancel":"cancel",
    "export":"export", "download":"export",
    "transfer":"transfer", "pay":"pay", "checkout":"pay",
}
_SENSITIVE = {"approve", "delete", "export", "transfer", "pay", "cancel"}


def _routes(context: AnalysisContext):
    items = [item for group in context.groups for item in group.observations] + context.ungrouped
    for item in items:
        if item.kind != "url":
            continue
        try:
            parsed = urlsplit(item.value)
            if not parsed.scheme or not parsed.netloc or parsed.username or parsed.password or not parsed.hostname:
                continue
            host = (item.host_key or parsed.hostname).lower().rstrip(".")
            segments = [part.lower() for part in parsed.path.split("/") if part]
            if not segments:
                continue
            normalized = [":id" if _ID.fullmatch(part) else part for part in segments]
            yield host, normalized, set(item.observation_ids)
        except ValueError:
            continue


def build_business_logic_profile(context: AnalysisContext, *, max_surfaces: int = 500) -> BusinessLogicProfile:
    """Build evidence-backed candidates; no network, method inference, or vulnerability claims."""
    if not 1 <= max_surfaces <= 2000:
        raise ValueError("invalid business logic surface limit")
    objects = {}
    actions = {}
    for host, parts, ids in _routes(context):
        resource_index = next((i for i, part in enumerate(parts) if part in _RESOURCES), None)
        resource = _RESOURCES[parts[resource_index]] if resource_index is not None else None
        if resource is not None:
            collection = "/" + "/".join(parts[:resource_index + 1])
            key = (host, resource, collection)
            entry = objects.setdefault(key, {"ids": set(), "object": None})
            entry["ids"].update(ids)
            if len(parts) > resource_index + 1 and parts[resource_index + 1] == ":id":
                entry["object"] = "/" + "/".join(parts[:resource_index + 2])
        action_name = next((_ACTIONS[p] for p in parts if p in _ACTIONS), None)
        if action_name:
            route = "/" + "/".join(parts)
            related = resource
            key = (host, action_name, route, related)
            actions.setdefault(key, set()).update(ids)

    object_records = []
    action_records = []
    hypotheses = []
    for (host, resource, collection), entry in sorted(objects.items())[:max_surfaces]:
        object_ids = sorted(entry["ids"])[:500]
        object_records.append(BusinessObjectSurface(
            host=host, resource=resource, collection_route=collection,
            object_route=entry["object"], observation_ids=object_ids,
        ))
        if entry["object"]:
            hypotheses.append(BusinessLogicHypothesis(
                category="object_authorization",
                statement=f"Observed collection and identifier-shaped routes for {resource} may warrant object-level authorization review.",
                validation_questions=[
                    "Can a second authorized test account access only objects it owns?",
                    "Are read, update, and delete permissions enforced independently?",
                    "Does changing an object identifier expose another account's data?",
                ],
                supporting_observation_ids=object_ids,
            ))
    for (host, action, route, resource), ids in sorted(actions.items())[:max_surfaces]:
        action_ids = sorted(ids)[:500]
        action_records.append(BusinessActionSurface(
            host=host, action=action, route_template=route,
            related_resource=resource, observation_ids=action_ids,
        ))
        if action in _SENSITIVE:
            hypotheses.append(BusinessLogicHypothesis(
                category="sensitive_action",
                statement=f"An observed route name suggests a potentially sensitive {action} operation; its actual behavior is unknown.",
                validation_questions=[
                    "Is the action restricted to the intended role and object owner?",
                    "Are state and authorization rechecked server-side at execution time?",
                    "Can the action be repeated or invoked out of the intended workflow order?",
                ],
                supporting_observation_ids=action_ids,
            ))
    return BusinessLogicProfile(
        object_surfaces=object_records[:max_surfaces],
        action_surfaces=action_records[:max_surfaces],
        hypotheses=hypotheses[:max_surfaces],
    )
