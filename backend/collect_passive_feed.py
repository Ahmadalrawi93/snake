"""Bounded Certificate Transparency collector, isolated from the SNAKE worker.

This process contacts only the fixed crt.sh provider. It never resolves or
connects to target hosts. Scope input is operator-reviewed, not proof of
authorization; collected names remain untrusted passive observations.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.scope_policy import ScopePolicy, normalize_host

PROVIDER_HOST = "crt.sh"
PROVIDER_PATH = "/"
DNSDB_HOST = "api.dnsdb.info"
DNSDB_PATH = "/dnsdb/v2/lookup/rrset/name/"
DNSDB_MAX_RESPONSE_BYTES = 1024 * 1024
DNSDB_MAX_ROWS = 2000
DNSDB_QUERY_LIMIT = 1000
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SCOPE_RULES = 100
MAX_PROVIDER_QUERIES = 200
MAX_CERT_ROWS = 2000
MAX_FEED_RECORDS = 500
REQUEST_TIMEOUT_SECONDS = 12


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirects are disabled", headers, fp)


def load_scope(path: str | os.PathLike[str]) -> list[str]:
    """Load a deliberately simple operator-reviewed scope manifest."""
    p = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(p, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise ValueError("scope file must be regular and not group/world writable")
        if info.st_size < 2 or info.st_size > 32768:
            raise ValueError("scope file size is outside the allowed range")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(32769)
    finally:
        os.close(fd)
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {"approved_scope_rules"}:
        raise ValueError("scope file must contain only approved_scope_rules")
    rules = data["approved_scope_rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= MAX_SCOPE_RULES:
        raise ValueError("scope must contain 1 to 100 hostname rules")
    normalized: list[str] = []
    for rule in rules:
        if not isinstance(rule, str) or not rule or rule != rule.strip():
            raise ValueError("scope rules must be non-empty strings")
        if rule.startswith("*."):
            host = normalize_host(rule[2:])
            normalized.append("*." + host)
        else:
            normalized.append(normalize_host(rule))
    if len(set(normalized)) != len(normalized):
        raise ValueError("duplicate scope rules")
    return normalized


def _provider_url(query: str) -> str:
    # The origin and path are constants; only a validated hostname query varies.
    return "https://crt.sh/?"+urllib.parse.urlencode({"q": query, "output": "json"})


def fetch_ct_rows(query: str, *, opener=None) -> list[dict[str, Any]]:
    url = _provider_url(query)
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != PROVIDER_HOST
            or parsed.path != PROVIDER_PATH or parsed.port is not None):
        raise ValueError("provider URL failed fixed-origin validation")
    client = opener or urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "SNAKE-passive-collector/1.0"},
        method="GET",
    )
    with client.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        if response.status != 200:
            raise ValueError("CT provider returned a non-200 response")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("CT provider response exceeds 2 MiB")
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("CT provider returned invalid JSON") from exc
    if not isinstance(data, list) or len(data) > MAX_CERT_ROWS:
        raise ValueError("CT provider response must be an array of at most 2000 rows")
    if any(not isinstance(row, dict) for row in data):
        raise ValueError("CT provider response contains a malformed row")
    return data


def collect_ct_feed(scope_rules: list[str], *, fetcher=fetch_ct_rows) -> list[dict[str, str]]:
    """Query CT for in-scope names only; do not contact discovered hosts."""
    policy = ScopePolicy(scope_rules)
    queries: list[str] = []
    for rule in scope_rules:
        base = rule[2:] if rule.startswith("*.") else rule
        queries.extend([base, "%." + base])
    queries = list(dict.fromkeys(queries))
    if len(queries) > MAX_PROVIDER_QUERIES:
        raise ValueError("too many provider queries")

    records: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    fetched_at = datetime.now(timezone.utc).isoformat()
    for query in queries:
        # Queries are generated exclusively from canonical scope rules.
        rows = fetcher(query)
        for row in rows:
            names = row.get("name_value")
            if not isinstance(names, str):
                continue
            cert_id = str(row.get("id", ""))[:80]
            issuer = str(row.get("issuer_name", ""))[:300]
            timestamp = row.get("not_before")
            try:
                observed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
                if observed.tzinfo is None:
                    continue
                observed_at = observed.astimezone(timezone.utc).isoformat()
            except (TypeError, ValueError):
                continue
            for raw_name in names.splitlines():
                candidate = raw_name.strip().lower().rstrip(".")
                if candidate.startswith("*."):
                    candidate = candidate[2:]
                try:
                    host = normalize_host(candidate)
                except ValueError:
                    continue
                if not policy.check_url("https://" + host).allowed:
                    continue
                key = (host, cert_id, observed_at)
                if key in seen:
                    continue
                seen.add(key)
                evidence = f"ct_log=crt.sh; certificate_id={cert_id}; issuer={issuer}; fetched_at={fetched_at}"
                records.append({
                    "hostname": host, "kind": "hostname", "value": host,
                    "evidence": evidence[:8000], "source": "crt_sh_ct",
                    "observed_at": observed_at,
                })
                if len(records) >= MAX_FEED_RECORDS:
                    return records
    return records


def write_feed(path: str | os.PathLike[str], records: list[dict[str, str]]) -> None:
    """Atomically create/replace a private feed without following a destination symlink."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise ValueError("output path must not be a symlink")
    payload = json.dumps(records, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > 1024 * 1024:
        raise ValueError("generated feed exceeds worker 1 MiB limit")
    fd, temp_name = tempfile.mkstemp(prefix=".snake-feed-", dir=str(destination.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if destination.is_symlink():
            raise ValueError("output path became a symlink")
        os.replace(temp_name, destination)
        os.chmod(destination, 0o600)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect passive CT names for an operator-reviewed scope")
    parser.add_argument("--scope-file", required=True, help="JSON file containing approved_scope_rules")
    parser.add_argument("--output", required=True, help="private JSON feed output path")
    parser.add_argument("--authorization-reference", required=True,
                        help="operator's audit reference; this is not independently verified")
    args = parser.parse_args()
    if not args.authorization_reference.strip() or len(args.authorization_reference) > 200:
        parser.error("authorization reference must be 1-200 characters")
    rules = load_scope(args.scope_file)
    records = collect_ct_feed(rules)
    write_feed(args.output, records)
    print(json.dumps({
        "provider": PROVIDER_HOST, "records": len(records),
        "scope_rules": len(rules), "authorization_reference": args.authorization_reference,
        "feed": str(args.output), "execution_enabled": False,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
