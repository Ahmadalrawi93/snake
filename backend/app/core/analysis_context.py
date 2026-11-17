"""Build deterministic analysis context from already persisted observations.

No network access, URL fetching, model calls, or vulnerability confirmation occurs here.
"""
from collections import defaultdict
from urllib.parse import urlsplit
from uuid import UUID

from app.schemas.analysis_context import (
    AnalysisContext, ContextObservation, ObservationGroup,
)
from app.schemas.worker_results import WorkerObservation


def _host_key(item: WorkerObservation) -> str | None:
    if item.kind == "hostname":
        value = item.value.rstrip(".").lower()
        return value or None
    if item.kind == "url":
        try:
            parsed = urlsplit(item.value)
            return parsed.hostname.lower().rstrip(".") if parsed.hostname else None
        except ValueError:
            return None
    return None


def build_analysis_context(
    observations: list[WorkerObservation],
    *,
    max_observations: int = 5000,
    max_evidence_chars: int = 2000,
) -> AnalysisContext:
    """Deduplicate exact semantic observations and group URL/hostname evidence."""
    if len(observations) > max_observations:
        raise ValueError("observation input exceeds analysis context limit")
    if not 1 <= max_evidence_chars <= 8192:
        raise ValueError("invalid evidence character limit")

    seen: set[tuple[str, str, str, str]] = set()
    grouped: dict[str, list[ContextObservation]] = defaultdict(list)
    ungrouped: list[ContextObservation] = []
    unique: list[ContextObservation] = []

    for item in observations:
        evidence = item.evidence[:max_evidence_chars]
        key = (item.kind, item.value, evidence, item.source)
        if key in seen:
            continue
        seen.add(key)
        host_key = _host_key(item)
        record = ContextObservation(
            observation_id=str(item.observation_id),
            kind=item.kind,
            value=item.value,
            evidence=evidence,
            source=item.source,
            host_key=host_key,
        )
        unique.append(record)
        if host_key:
            grouped[host_key].append(record)
        else:
            ungrouped.append(record)

    groups = [
        ObservationGroup(host_key=host, observations=items)
        for host, items in sorted(grouped.items())
    ]
    return AnalysisContext(
        total_observations=len(observations),
        unique_observations=len(unique),
        duplicate_count=len(observations) - len(unique),
        groups=groups,
        ungrouped=ungrouped,
    )
