"""Build a bounded, passive-only graph of observed attack-surface relationships."""
from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlsplit

MAX_RECORDS = 500
MAX_NODES = 1500
MAX_EDGES = 3000
API_PREFIXES = {"api", "graphql", "v1", "v2", "v3", "rest", "swagger", "openapi"}


def _id(kind: str, value: str) -> str:
    digest = hashlib.sha256((kind + "\\0" + value).encode("utf-8")).hexdigest()[:24]
    return f"{kind}:{digest}"


def _scope_for(host: str, rules: list[str]) -> str | None:
    matches = []
    for rule in rules:
        if not isinstance(rule, str):
            continue
        wildcard = rule.startswith("*.")
        base = rule[2:] if wildcard else rule
        if host == base and not wildcard:
            matches.append(rule)
        elif host.endswith("." + base):
            matches.append(rule)
    return min(matches, key=len) if matches else None


def build_attack_surface_graph(
    records: list[dict[str, Any]],
    scope_rules: list[str],
) -> dict[str, Any]:
    """Create evidence-linked nodes/edges; no inference of reachability or vulnerability."""
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("graph input must contain at most 500 passive records")
    if not isinstance(scope_rules, list) or not 1 <= len(scope_rules) <= 100:
        raise ValueError("graph requires 1 to 100 approved scope rules")

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_node(kind: str, value: str, **attrs: Any) -> str:
        node_id = _id(kind, value)
        if node_id not in nodes:
            if len(nodes) >= MAX_NODES:
                raise ValueError("graph node limit exceeded")
            nodes[node_id] = {"id": node_id, "type": kind, "value": value, **attrs}
        return node_id

    def add_edge(source: str, target: str, relation: str, evidence: dict[str, str]) -> None:
        key = (source, target, relation)
        if key not in edges:
            if len(edges) >= MAX_EDGES:
                raise ValueError("graph edge limit exceeded")
            edges[key] = {"source": source, "target": target, "relation": relation, "evidence": []}
        refs = edges[key]["evidence"]
        if len(refs) < 20 and evidence not in refs:
            refs.append(evidence)

    for record in records:
        if not isinstance(record, dict):
            continue
        host, kind, value, source = (
            record.get("hostname"), record.get("kind"), record.get("value"), record.get("source")
        )
        observed = record.get("observed_at")
        if not all(isinstance(x, str) and x for x in (host, kind, value, source, observed)):
            continue
        if len(host) > 253 or len(value) > 4096 or len(source) > 100:
            continue
        scope = _scope_for(host.lower().rstrip("."), scope_rules)
        if scope is None:
            continue
        evidence = {"source": source, "observed_at": observed}
        host_id = add_node("hostname", host.lower().rstrip("."))
        scope_id = add_node("scope_rule", scope)
        add_edge(host_id, scope_id, "matches_approved_scope_rule", evidence)

        if kind == "url":
            try:
                parsed = urlsplit(value)
                if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                        or parsed.username is not None or parsed.password is not None
                        or parsed.query or parsed.fragment or parsed.hostname.lower().rstrip(".") != host.lower().rstrip(".")):
                    continue
                normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
                url_id = add_node("url", normalized_url)
                add_edge(url_id, host_id, "observed_on_hostname", evidence)
                path_parts = [part.lower() for part in parsed.path.split("/") if part]
                if path_parts and path_parts[0] in API_PREFIXES:
                    route_id = add_node("api_route_hint", normalized_url)
                    add_edge(route_id, url_id, "passive_api_path_hint", evidence)
            except ValueError:
                continue
        elif kind in {"technology", "dns_record", "http_header"}:
            observation_id = add_node("observation", f"{kind}:{value}")
            add_edge(observation_id, host_id, "observed_for_hostname", evidence)

    ordered_nodes = sorted(nodes.values(), key=lambda item: (item["type"], item["value"]))
    ordered_edges = sorted(edges.values(), key=lambda item: (item["source"], item["relation"], item["target"]))
    return {
        "schema_version": 1,
        "classification": "passive_unconfirmed_attack_surface_graph",
        "execution_enabled": False,
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "summary": {
            "nodes": len(ordered_nodes),
            "edges": len(ordered_edges),
            "api_route_hints": sum(node["type"] == "api_route_hint" for node in ordered_nodes),
        },
    }
