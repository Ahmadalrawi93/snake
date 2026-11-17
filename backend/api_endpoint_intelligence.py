"""Passive API endpoint hints from in-scope URL observations; never probe endpoints."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from app.core.scope_policy import host_matches, normalize_host

MAX_RECORDS = 500
MAX_ENDPOINTS = 1000
UUID_RE = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
LONG_HEX_RE = re.compile(r"(?i)^[0-9a-f]{16,}$")
NUMERIC_RE = re.compile(r"^\d{2,}$")
SENSITIVE_SEGMENTS = {
    "auth": {"auth", "oauth", "sso", "login", "logout", "token", "session"},
    "identity": {"user", "users", "account", "accounts", "profile", "me"},
    "administration": {"admin", "administrator", "management", "manage"},
    "commerce": {"payment", "payments", "billing", "checkout", "invoice", "orders"},
    "documentation": {"swagger", "openapi", "docs", "redoc"},
    "graphql": {"graphql"},
    "api_versioned": {"v1", "v2", "v3", "api"},
}
ACTION_SEGMENTS = {"create", "update", "delete", "remove", "cancel", "approve", "reject", "refund", "transfer", "export", "import", "invite", "reset", "verify", "confirm", "publish"}
RESOURCE_SEGMENTS = {"user", "users", "account", "accounts", "profile", "order", "orders", "payment", "payments", "invoice", "invoices", "subscription", "subscriptions", "role", "roles", "permission", "permissions", "document", "documents", "file", "files", "organization", "organizations"}


def _scope_rule(host: str, rules: list[str]) -> str | None:
    matches = []
    for rule in rules:
        try:
            if isinstance(rule, str) and host_matches(host, rule):
                matches.append(rule)
        except ValueError:
            continue
    return min(matches, key=len) if matches else None


def _template_path(path: str) -> str:
    parts = []
    for segment in path.split("/"):
        if not segment:
            continue
        if UUID_RE.fullmatch(segment) or LONG_HEX_RE.fullmatch(segment) or NUMERIC_RE.fullmatch(segment):
            parts.append("{id}")
        else:
            parts.append(segment[:100])
    return "/" + "/".join(parts) if parts else "/"


def _path_intelligence(path: str) -> dict[str, Any]:
    segments = [part.lower() for part in path.split("/") if part]
    categories = sorted(category for category, words in SENSITIVE_SEGMENTS.items() if set(segments) & words)
    resources = sorted(set(segments) & RESOURCE_SEGMENTS)
    actions = sorted(set(segments) & ACTION_SEGMENTS)
    object_reference = "{id}" in segments
    review_hints = []
    if object_reference and resources:
        review_hints.append("object_reference_authorization_review")
    if actions:
        review_hints.append("named_business_operation_manual_review")
    if "administration" in categories or "identity" in categories:
        review_hints.append("privileged_or_identity_surface_manual_review")
    return {
        "categories": categories,
        "resource_segments": resources,
        "action_segments": actions,
        "object_reference_present": object_reference,
        "business_logic_review_hints": sorted(review_hints),
    }


def _endpoint_id(host: str, path: str) -> str:
    digest = hashlib.sha256(f"{host}\0{path}".encode()).hexdigest()[:24]
    return f"api_endpoint:{digest}"


def build_api_endpoint_intelligence(
    records: list[dict[str, Any]], scope_rules: list[str]
) -> dict[str, Any]:
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("endpoint intelligence accepts at most 500 records")
    if not isinstance(scope_rules, list) or not 1 <= len(scope_rules) <= 100:
        raise ValueError("endpoint intelligence requires 1 to 100 approved scope rules")

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("kind") != "url":
            continue
        host, value, source, observed = (
            record.get("hostname"), record.get("value"), record.get("source"), record.get("observed_at")
        )
        if not all(isinstance(x, str) and x for x in (host, value, source, observed)):
            continue
        if len(value) > 4096 or len(source) > 100 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            continue
        try:
            timestamp = datetime.fromisoformat(observed.replace("Z", "+00:00"))
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                continue
            canonical_host = normalize_host(host)
            parsed = urlsplit(value)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or parsed.query or parsed.fragment or parsed.port is not None and not 1 <= parsed.port <= 65535
                    or normalize_host(parsed.hostname) != canonical_host):
                continue
        except ValueError:
            continue
        scope = _scope_rule(canonical_host, scope_rules)
        if scope is None:
            continue
        path = _template_path(parsed.path)
        key = (canonical_host, path)
        if key not in grouped:
            if len(grouped) >= MAX_ENDPOINTS:
                raise ValueError("API endpoint limit exceeded")
            grouped[key] = {
                "id": _endpoint_id(canonical_host, path),
                "hostname": canonical_host,
                "path_template": path,
                "scope_rule": scope,
                "method": "unknown",
                **_path_intelligence(path),
                "evidence": [],
            }
        evidence = {"source": source, "observed_at": observed}
        if evidence not in grouped[key]["evidence"] and len(grouped[key]["evidence"]) < 20:
            grouped[key]["evidence"].append(evidence)

    endpoints = sorted(grouped.values(), key=lambda row: (row["hostname"], row["path_template"]))
    return {
        "schema_version": 1,
        "classification": "passive_unconfirmed_api_endpoint_hints",
        "execution_enabled": False,
        "endpoints": endpoints,
        "summary": {
            "endpoints": len(endpoints),
            "categorized": sum(bool(row["categories"]) for row in endpoints),
            "method_known": 0,
        },
    }
