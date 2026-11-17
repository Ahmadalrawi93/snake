"""Deterministic correlation of passive observations; never performs requests."""
from collections import defaultdict
import re
from urllib.parse import urlsplit

from app.schemas.analysis_context import AnalysisContext, ContextObservation
from app.schemas.evidence_correlation import CorrelationReport, EvidenceLink


_ID_SEGMENT = re.compile(r"^(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})$", re.I)
_AUTH_TERMS = {"login", "logout", "signin", "signout", "auth", "oauth", "token", "session"}
_OBJECT_TERMS = {"user", "users", "account", "accounts", "profile", "profiles", "order", "orders", "invoice", "invoices"}


def _path(item: ContextObservation) -> tuple[str, list[str]] | None:
    if item.kind != "url":
        return None
    try:
        parsed = urlsplit(item.value)
        if not parsed.scheme or not parsed.netloc or parsed.username or parsed.password:
            return None
        segments = [s for s in parsed.path.split("/") if s]
        normalized = [":id" if _ID_SEGMENT.fullmatch(s) else s.lower() for s in segments]
        return (item.host_key or parsed.hostname or "", normalized)
    except ValueError:
        return None


def correlate_analysis_context(context: AnalysisContext, *, max_links: int = 1000) -> CorrelationReport:
    """Produce explainable candidate relationships while retaining evidence provenance."""
    if not 1 <= max_links <= 5000:
        raise ValueError("invalid correlation link limit")

    all_items = [item for group in context.groups for item in group.observations] + context.ungrouped
    links: list[EvidenceLink] = []
    linked: set[str] = set()

    by_host: dict[str, list[ContextObservation]] = defaultdict(list)
    by_route: dict[tuple[str, tuple[str, ...]], list[ContextObservation]] = defaultdict(list)
    auth_items: dict[str, list[ContextObservation]] = defaultdict(list)
    object_items: dict[str, list[ContextObservation]] = defaultdict(list)

    for item in all_items:
        if item.host_key:
            by_host[item.host_key].append(item)
        parsed = _path(item)
        if parsed:
            host, segments = parsed
            by_route[(host, tuple(segments))].append(item)
            terms = {s.lower() for s in segments}
            if terms & _AUTH_TERMS:
                auth_items[host].append(item)
            if terms & _OBJECT_TERMS:
                object_items[host].append(item)

    def add(items: list[ContextObservation], relation: str, rationale: str):
        ids = sorted({oid for item in items for oid in item.observation_ids})
        if len(ids) < 2 or len(links) >= max_links:
            return
        links.append(EvidenceLink(observation_ids=ids, relation=relation, rationale=rationale))
        linked.update(ids)

    for host, items in sorted(by_host.items()):
        if len({oid for item in items for oid in item.observation_ids}) >= 2:
            add(items, "same_host", "Multiple observations refer to the same normalized host.")
    for (host, route), items in sorted(by_route.items()):
        if len({oid for item in items for oid in item.observation_ids}) >= 2:
            add(items, "same_route_family", f"Observations share route shape on {host}: /{'/'.join(route)}")
    for host, items in sorted(auth_items.items()):
        add(items, "authentication_surface", "Route names contain authentication-related terms; behavior is not established.")
    for host, items in sorted(object_items.items()):
        add(items, "potential_object_access_surface", "Route names contain object/account-related terms; authorization behavior is not established.")

    all_ids = sorted({oid for item in all_items for oid in item.observation_ids})
    return CorrelationReport(
        input_observation_count=context.total_observations,
        links=links,
        uncorrelated_observation_ids=[oid for oid in all_ids if oid not in linked],
    )
