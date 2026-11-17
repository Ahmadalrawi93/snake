"""Build a deterministic application surface inventory from existing observations."""
import re
from collections import defaultdict
from urllib.parse import urlsplit

from app.core.analysis_redaction import redact_text
from app.schemas.analysis_context import AnalysisContext
from app.schemas.application_profile import (
    ApplicationHost, ApplicationProfile, ApplicationRoute, ApplicationTechnology,
)

_ID_SEGMENT = re.compile(r"^(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})$", re.I)
_ROUTE_TERMS = {
    "authentication": {"login", "logout", "signin", "signout", "auth", "oauth", "token", "session"},
    "object_access": {"user", "users", "account", "accounts", "profile", "profiles", "order", "orders", "invoice", "invoices"},
    "account": {"me", "settings", "password", "security", "preferences"},
    "payment": {"payment", "payments", "billing", "invoice", "invoices", "checkout", "subscription"},
    "admin": {"admin", "administrator", "dashboard", "manage", "management"},
}


def build_application_profile(context: AnalysisContext, *, max_routes: int = 1000) -> ApplicationProfile:
    """Summarize only observed host, technology and URL data; never probes an application."""
    if not 1 <= max_routes <= 5000:
        raise ValueError("invalid application route limit")

    all_items = [item for group in context.groups for item in group.observations] + context.ungrouped
    hosts: dict[str, set[str]] = defaultdict(set)
    technologies: dict[str, dict[str, set[str] | str]] = {}
    routes: dict[tuple[str, str], set[str]] = defaultdict(set)

    for item in all_items:
        ids = set(item.observation_ids)
        if item.kind == "hostname" and item.host_key:
            hosts[item.host_key].update(ids)
        elif item.kind == "url":
            try:
                parsed = urlsplit(item.value)
                host = (item.host_key or parsed.hostname or "").lower().rstrip(".")
                if not host or not parsed.scheme or not parsed.netloc or parsed.username or parsed.password:
                    continue
                hosts[host].update(ids)
                segments = [segment for segment in parsed.path.split("/") if segment]
                normalized = [":id" if _ID_SEGMENT.fullmatch(segment) else redact_text(segment.lower()) for segment in segments]
                route = "/" + "/".join(normalized)
                route = route[:1024] or "/"
                routes[(host, route)].update(ids)
            except ValueError:
                continue
        elif item.kind == "technology":
            name = redact_text(item.value.strip())[:160]
            if not name:
                continue
            entry = technologies.setdefault(name.casefold(), {"name": name, "ids": set(), "evidence": redact_text(item.evidence)[:500]})
            entry["ids"].update(ids)
        elif item.kind == "http_header":
            # Header observations are retained as technology clues only when they
            # explicitly name a known software-identifying header.
            raw = redact_text(item.value.strip())
            if ":" in raw:
                header, value = raw.split(":", 1)
                if header.strip().casefold() in {"server", "x-powered-by", "x-aspnet-version", "x-generator"} and value.strip():
                    name = f"{header.strip()}: {value.strip()}"[:160]
                    entry = technologies.setdefault(name.casefold(), {"name": name, "ids": set(), "evidence": redact_text(item.evidence)[:500]})
                    entry["ids"].update(ids)

    route_items = sorted(routes.items())[:max_routes]
    route_records = []
    for (host, route), ids in route_items:
        segments = {part.lower() for part in route.split("/") if part and part != ":id"}
        surfaces = sorted({surface for surface, terms in _ROUTE_TERMS.items() if segments & terms})
        route_records.append(ApplicationRoute(
            host=host, route_template=route, surfaces=surfaces, observation_ids=sorted(ids)[:500]
        ))

    return ApplicationProfile(
        source_observation_count=context.total_observations,
        hosts=[
            ApplicationHost(hostname=host, observation_ids=sorted(ids)[:500])
            for host, ids in sorted(hosts.items())[:500]
        ],
        technologies=[
            ApplicationTechnology(name=entry["name"], observation_ids=sorted(entry["ids"])[:500], evidence=entry["evidence"])
            for _, entry in sorted(technologies.items())[:500]
        ],
        routes=route_records,
    )
