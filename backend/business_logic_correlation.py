"""Correlate passive API path shapes into review hypotheses; never assert vulnerabilities."""
from __future__ import annotations

import hashlib
from typing import Any

MAX_ENDPOINTS = 1000
MAX_HYPOTHESES = 1000
RESOURCE_NAMES = {
    "user", "users", "account", "accounts", "profile", "profiles",
    "order", "orders", "payment", "payments", "invoice", "invoices",
    "subscription", "subscriptions", "role", "roles", "permission", "permissions",
    "document", "documents", "file", "files", "organization", "organizations",
    "project", "projects",
}
ACTION_NAMES = {
    "approve", "reject", "refund", "transfer", "cancel", "delete", "remove",
    "update", "create", "publish", "export", "import", "invite", "verify",
    "confirm", "reset", "pay", "checkout",
}


def _id(kind: str, *parts: str) -> str:
    raw = "\0".join((kind, *parts))
    return f"{kind}:{hashlib.sha256(raw.encode()).hexdigest()[:24]}"


def _segments(path: str) -> list[str]:
    return [part.lower() for part in path.split("/") if part]


def correlate_business_logic(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    """Produce review candidates from already-collected, in-scope passive endpoint hints."""
    if not isinstance(endpoints, list) or len(endpoints) > MAX_ENDPOINTS:
        raise ValueError("business logic correlation accepts at most 1000 endpoints")

    grouped: dict[str, dict[str, Any]] = {}
    for item in endpoints:
        if not isinstance(item, dict):
            continue
        host, path = item.get("hostname"), item.get("path_template")
        if not isinstance(host, str) or not host or len(host) > 253:
            continue
        if not isinstance(path, str) or not path.startswith("/") or len(path) > 1024:
            continue
        segments = _segments(path)
        if not segments:
            continue
        key = host.lower().rstrip(".")
        bucket = grouped.setdefault(key, {"collections": {}, "objects": {}, "actions": {}})
        resources = set(segments) & RESOURCE_NAMES
        actions = set(segments) & ACTION_NAMES
        ids = item.get("evidence", [])
        refs = []
        if isinstance(ids, list):
            for ref in ids[:20]:
                if isinstance(ref, dict):
                    source, observed = ref.get("source"), ref.get("observed_at")
                    if isinstance(source, str) and isinstance(observed, str):
                        refs.append({"source": source[:100], "observed_at": observed[:64]})
        for resource in resources:
            index = segments.index(resource)
            prefix = "/" + "/".join(segments[:index + 1])
            if len(segments) == index + 1:
                bucket["collections"].setdefault(resource, {}).setdefault(prefix, refs)
            if len(segments) == index + 2 and segments[index + 1] == "{id}":
                object_path = "/" + "/".join(segments[:index + 2])
                bucket["objects"].setdefault(resource, {}).setdefault(object_path, refs)
        if actions:
            for action in sorted(actions):
                related = next((resource for resource in sorted(resources) if resource in segments), None)
                route = "/" + "/".join(segments)
                bucket["actions"].setdefault((related or "unknown", action, route), refs)

    hypotheses = []
    for host, bucket in sorted(grouped.items()):
        for resource, objects in sorted(bucket["objects"].items()):
            collections = bucket["collections"].get(resource, {})
            if not collections:
                continue
            for object_path, object_refs in sorted(objects.items()):
                collection_path = max(collections, key=len)
                refs = (collections[collection_path] + object_refs)[:40]
                category = "object_authorization"
                statement = (
                    f"Passive observations show both {resource} collection and identifier-shaped routes on {host}; "
                    "review object-level authorization using two controlled test accounts."
                )
                questions = [
                    "Can account B read an object created by account A?",
                    "Are update and delete authorization checks enforced for every object identifier?",
                    "Do ownership checks remain effective when identifiers are changed or replayed?",
                ]
                hypotheses.append({
                    "id": _id(category, host, collection_path, object_path),
                    "category": category,
                    "host": host,
                    "resource": resource,
                    "related_routes": [collection_path, object_path],
                    "supporting_evidence": refs,
                    "validation_questions": questions,
                    "priority": "high" if len(refs) >= 3 else "medium",
                    "disposition": "requires_independent_validation",
                    "confirmed": False,
                })
        for (resource, action, route), refs in sorted(bucket["actions"].items()):
            if not refs:
                continue
            category = "sensitive_business_operation"
            priority = "high" if action in {"refund", "transfer", "delete", "approve", "pay"} else "medium"
            hypotheses.append({
                "id": _id(category, host, resource, action, route),
                "category": category,
                "host": host,
                "resource": resource,
                "action": action,
                "related_routes": [route],
                "supporting_evidence": refs[:20],
                "validation_questions": [
                    "Is this operation restricted to the intended role and object owner?",
                    "Is the allowed state transition checked server-side at execution time?",
                    "Can the operation be replayed or invoked out of the intended workflow order?",
                    "Are duplicate requests idempotent where the business process requires it?",
                ],
                "priority": priority,
                "disposition": "requires_independent_validation",
                "confirmed": False,
            })

    hypotheses.sort(key=lambda row: (
        {"high": 0, "medium": 1, "low": 2}[row["priority"]],
        row["category"], row["host"], row["id"],
    ))
    if len(hypotheses) > MAX_HYPOTHESES:
        raise ValueError("business logic hypothesis limit exceeded")
    return {
        "schema_version": 1,
        "classification": "passive_unconfirmed_business_logic_hypotheses",
        "execution_enabled": False,
        "hypotheses": hypotheses,
        "summary": {
            "total": len(hypotheses),
            "object_authorization": sum(x["category"] == "object_authorization" for x in hypotheses),
            "sensitive_business_operation": sum(x["category"] == "sensitive_business_operation" for x in hypotheses),
            "high_priority": sum(x["priority"] == "high" for x in hypotheses),
            "confirmed": 0,
        },
        "limitations": "Path shapes and names do not prove endpoint reachability, supported methods, ownership, roles, state transitions, authorization defects, or vulnerabilities.",
    }
