"""Deterministic prioritization of passive assets; scores are triage hints, not risk."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

MAX_RECORDS = 500
SOURCE_POINTS = 8
MAX_SOURCE_POINTS = 24
EVENT_POINTS = {"new": 20, "returned": 12, "missing": -10}
KIND_POINTS = {"url": 12, "technology": 8, "http_header": 6, "dns_record": 5, "hostname": 3}


def _age_points(observed_at: str, now: datetime) -> int:
    try:
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        if observed.tzinfo is None:
            return 0
        age_days = max(0.0, (now - observed.astimezone(timezone.utc)).total_seconds() / 86400)
    except (TypeError, ValueError):
        return 0
    if age_days <= 1:
        return 20
    if age_days <= 7:
        return 15
    if age_days <= 30:
        return 8
    if age_days <= 90:
        return 3
    return 0


def prioritize_assets(
    records: list[dict[str, Any]],
    *,
    events: list[dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Rank records using freshness, independent source count, kind, and change events."""
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("prioritization accepts at most 500 records")
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        raise ValueError("reference time must be timezone-aware")
    event_map: dict[tuple[str, str], str] = {}
    for event in events or []:
        if not isinstance(event, dict):
            continue
        host, kind, event_type = event.get("hostname"), event.get("kind"), event.get("event")
        if isinstance(host, str) and isinstance(kind, str) and event_type in EVENT_POINTS:
            event_map[(host, kind)] = event_type

    sources: dict[tuple[str, str], set[str]] = {}
    for item in records:
        if not isinstance(item, dict):
            continue
        host, kind, source = item.get("hostname"), item.get("kind"), item.get("source")
        if all(isinstance(x, str) and x for x in (host, kind, source)):
            sources.setdefault((host, kind), set()).add(source)

    ranked = []
    for item in records:
        if not isinstance(item, dict):
            continue
        host, kind, source = item.get("hostname"), item.get("kind"), item.get("source")
        observed_at = item.get("observed_at")
        if not all(isinstance(x, str) and x for x in (host, kind, source, observed_at)):
            continue
        key = (host, kind)
        source_count = len(sources.get(key, set()))
        source_score = min(MAX_SOURCE_POINTS, max(0, source_count - 1) * SOURCE_POINTS)
        event = event_map.get(key)
        freshness = _age_points(observed_at, clock)
        kind_score = KIND_POINTS.get(kind, 0)
        change_score = EVENT_POINTS.get(event, 0)
        score = freshness + source_score + kind_score + change_score
        ranked.append({
            **item,
            "priority_score": score,
            "priority_factors": {
                "freshness": freshness,
                "independent_sources": source_score,
                "asset_type": kind_score,
                "recent_change": change_score,
            },
            "priority_event": event or "none",
            "priority_label": "high" if score >= 45 else "medium" if score >= 25 else "low",
        })
    ranked.sort(key=lambda row: (-row["priority_score"], row["hostname"], row["kind"], row["source"]))
    return ranked
