"""Deterministic security-signal extraction from verified worker observations.

Signals are leads for human validation, never confirmed vulnerabilities. The
engine performs no network requests and never upgrades severity from a heuristic.
"""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

_VERSION = re.compile(r"(?:\b\d+\.\d+(?:\.\d+)?\b)")
_BACKUP_SUFFIXES = (".bak", ".backup", ".old", ".orig", ".save", ".swp", ".zip", ".tar", ".gz", ".sql")
_SENSITIVE_PATHS = {
    "/.env": ("possible_environment_file", "A URL observation points to a conventional environment-file path."),
    "/.git/config": ("possible_git_metadata", "A URL observation points to Git repository metadata."),
    "/server-status": ("possible_server_status_page", "A URL observation points to a server status endpoint."),
    "/debug": ("possible_debug_endpoint", "A URL observation points to a conventional debug endpoint."),
}


class SecuritySignal(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    signal_id: str = Field(min_length=1, max_length=80)
    category: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=180)
    confidence: str = Field(pattern=r"^(low|medium)$")
    disposition: str = "requires_validation"
    severity: str = "not_assessed"
    host: str = Field(min_length=1, max_length=253)
    rationale: str = Field(min_length=1, max_length=1000)
    evidence_observation_ids: list[str] = Field(min_length=1, max_length=50)
    validation_guidance: str = Field(min_length=1, max_length=1000)


class SecuritySignalReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    source_observation_count: int = Field(ge=0)
    signal_count: int = Field(ge=0)
    signals: list[SecuritySignal] = Field(max_length=500)
    limitations: list[str]


def _host(item: dict) -> str:
    value = str(item.get("host_key") or "").strip().lower().rstrip(".")
    if value:
        return value
    try:
        return (urlsplit(str(item.get("value", ""))).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _header(item: dict) -> tuple[str, str] | None:
    if item.get("kind") != "http_header":
        return None
    raw = str(item.get("value", ""))
    if ":" not in raw:
        return None
    name, value = raw.split(":", 1)
    name = name.strip().lower()
    if not re.fullmatch(r"[a-z0-9-]{1,80}", name):
        return None
    return name, value.strip()


def analyze_security_signals(observations: list[dict], *, max_signals: int = 500) -> SecuritySignalReport:
    """Extract conservative, explainable leads from persisted observations."""
    if not 1 <= max_signals <= 500:
        raise ValueError("max_signals must be between 1 and 500")

    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in observations:
        host = _host(item)
        if host:
            grouped[host].append(item)

    signals: list[SecuritySignal] = []

    def add(host: str, category: str, title: str, confidence: str,
            rationale: str, ids: set[str], guidance: str):
        if len(signals) >= max_signals or not ids:
            return
        stable = "|".join((host, category, ",".join(sorted(ids))))
        import hashlib
        signal_id = hashlib.sha256(stable.encode()).hexdigest()[:32]
        signals.append(SecuritySignal(
            signal_id=signal_id, category=category, title=title,
            confidence=confidence, host=host, rationale=rationale,
            evidence_observation_ids=sorted(ids)[:50],
            validation_guidance=guidance,
        ))

    for host, items in sorted(grouped.items()):
        headers: dict[str, list[dict]] = defaultdict(list)
        for item in items:
            parsed = _header(item)
            if parsed:
                headers[parsed[0]].append(item)
        for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            for item in headers.get(name, []):
                parsed = _header(item)
                if parsed and _VERSION.search(parsed[1]):
                    add(host, "technology_disclosure", "Version-bearing server header",
                        "low", f"The {name} response header exposes a version-like value; this alone does not establish an exploitable vulnerability.",
                        {str(item.get("observation_id", ""))},
                        "Verify the exact response and determine whether the disclosed version is outdated and affected by a known vulnerability.")

        origins = headers.get("access-control-allow-origin", [])
        credentials = headers.get("access-control-allow-credentials", [])
        wildcard_items = [x for x in origins if (_header(x) or ("", ""))[1] == "*"]
        true_credentials = [x for x in credentials if (_header(x) or ("", ""))[1].lower() == "true"]
        if wildcard_items and true_credentials:
            add(host, "cors_configuration", "Wildcard CORS origin combined with credentials",
                "medium", "Observed Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true on the same host. Browser enforcement and endpoint behavior still require validation.",
                {str(x.get("observation_id", "")) for x in wildcard_items + true_credentials},
                "Reproduce on the exact endpoint in a browser and verify credentialed cross-origin response behavior; do not infer data exposure from headers alone.")

        for item in headers.get("set-cookie", []):
            parsed = _header(item)
            if not parsed:
                continue
            cookie_pair = parsed[1].split(";", 1)[0]
            cookie_name = cookie_pair.split("=", 1)[0].strip()
            attributes = {part.strip().split("=", 1)[0].lower() for part in parsed[1].split(";")[1:]}
            missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in attributes]
            if missing and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", cookie_name):
                add(host, "cookie_configuration", f"Cookie {cookie_name} missing security attributes",
                    "low", f"Observed Set-Cookie lacks: {', '.join(missing)}. Cookie value is deliberately excluded from the signal.",
                    {str(item.get("observation_id", ""))},
                    "Inspect the cookie in the browser and assess its purpose, transport, script access, and cross-site requirements before reporting.")

        for item in items:
            if item.get("kind") != "url":
                continue
            raw_url = str(item.get("value", ""))
            try:
                parsed = urlsplit(raw_url)
            except ValueError:
                continue
            path = parsed.path.lower()
            if parsed.scheme.lower() == "http":
                add(host, "transport_security", "HTTP URL observed",
                    "low", "The collected URL uses cleartext HTTP; verify whether sensitive traffic or authentication is actually served without TLS.",
                    {str(item.get("observation_id", ""))},
                    "Check the final canonical URL, redirect behavior, and whether sensitive content or credentials are transmitted over HTTP.")
            match = _SENSITIVE_PATHS.get(path)
            if match:
                add(host, match[0], "Potentially sensitive conventional path observed",
                    "low", match[1] + " URL discovery is not proof that the resource exists or is accessible.",
                    {str(item.get("observation_id", ""))},
                    "Request only within the approved scope and verify status, content type, and whether the response contains non-public material.")
            elif path.endswith(_BACKUP_SUFFIXES):
                add(host, "possible_backup_file", "Potential backup-file URL observed",
                    "low", "A discovered URL has a conventional backup or archive suffix; this is not proof that the resource exists or is exposed.",
                    {str(item.get("observation_id", ""))},
                    "Verify the exact resource safely and confirm that it contains sensitive application data before reporting.")

    return SecuritySignalReport(
        source_observation_count=len(observations),
        signal_count=len(signals),
        signals=signals,
        limitations=[
            "Signals are leads, not confirmed vulnerabilities.",
            "No target requests, payloads, authentication bypasses, or exploitation are performed.",
            "Missing headers cannot be inferred from an incomplete header feed.",
            "Severity and CVSS remain not_assessed until independent validation.",
        ],
    )
