"""Conservative cross-surface reasoning over already observed route evidence."""
import re
from collections import defaultdict
from urllib.parse import urlsplit

from app.schemas.analysis_context import AnalysisContext
from app.schemas.business_logic import BusinessLogicProfile
from app.schemas.cross_surface import CrossSurfaceLink, CrossSurfaceProfile


_AUTH_TERMS = {"login", "logout", "signin", "signout", "auth", "oauth", "token", "session"}
_SENSITIVE = {"approve", "delete", "export", "transfer", "pay", "cancel"}
_ID = re.compile(r"^(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})$", re.I)


def _authentication_routes(context: AnalysisContext) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
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
            if any(part in _AUTH_TERMS for part in segments):
                result[host].update(item.observation_ids)
        except ValueError:
            continue
    return result


def build_cross_surface_profile(
    context: AnalysisContext,
    business: BusinessLogicProfile,
    *,
    max_links: int = 500,
) -> CrossSurfaceProfile:
    """Link co-occurring route families; never infer shared controls or exploitability."""
    if not 1 <= max_links <= 2000:
        raise ValueError("invalid cross-surface link limit")
    auth = _authentication_routes(context)
    objects: dict[str, set[str]] = defaultdict(set)
    actions: dict[str, set[str]] = defaultdict(set)
    for surface in business.object_surfaces:
        if surface.object_route is not None:
            objects[surface.host].update(surface.observation_ids)
    for surface in business.action_surfaces:
        if surface.action in _SENSITIVE:
            actions[surface.host].update(surface.observation_ids)

    links: list[CrossSurfaceLink] = []

    def add(host: str, relation: str, ids: set[str], rationale: str, questions: list[str]) -> None:
        if len(ids) < 2 or len(links) >= max_links:
            return
        links.append(CrossSurfaceLink(
            host=host, relation=relation, observation_ids=sorted(ids)[:500],
            rationale=rationale, validation_questions=questions,
        ))

    for host in sorted(set(auth) & set(objects)):
        add(host, "authentication_to_object_surface", auth[host] | objects[host],
            "Authentication-related and object-resource routes were both observed on this host; shared controls are unknown.",
            ["Do the routes use the same documented authentication boundary?",
             "Are object reads and writes independently authorized for each test account?",
             "Do unauthenticated and lower-privilege requests receive the expected denial?"])
    for host in sorted(set(auth) & set(actions)):
        add(host, "authentication_to_sensitive_action", auth[host] | actions[host],
            "Authentication-related and potentially sensitive action routes co-occur on this host; enforcement is unknown.",
            ["Is the action restricted to the intended authenticated role?",
             "Is authorization checked server-side at the action endpoint?",
             "Are state and ownership revalidated when the action executes?"])
    for host in sorted(set(objects) & set(actions)):
        add(host, "object_to_sensitive_action", objects[host] | actions[host],
            "Object-resource and potentially sensitive action routes co-occur on this host; their relationship is unproven.",
            ["Is the action bound to the intended object and owner?",
             "Can a user act on an object outside their permitted scope?",
             "Are workflow transitions enforced server-side?"])
    return CrossSurfaceProfile(links=links[:max_links])
