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



def _dnsdb_url(query: str) -> str:
    candidate = query[2:] if query.startswith("*.") else query
    normalized = normalize_host(candidate)
    if query != normalized and query != "*." + normalized:
        raise ValueError("DNSDB query must be a canonical hostname or wildcard scope")
    encoded = urllib.parse.quote(query, safe="*.-")
    return f"https://{DNSDB_HOST}{DNSDB_PATH}{encoded}?limit={DNSDB_QUERY_LIMIT}"


def fetch_dnsdb_rows(query: str, api_key: str, *, opener=None) -> tuple[list[dict[str, Any]], str]:
    """Fetch one DNSDB v2 SAF/NDJSON response from the fixed provider."""
    if (not isinstance(api_key, str) or not api_key or len(api_key) > 4096
            or any(ord(char) < 33 or ord(char) > 126 for char in api_key)):
        raise ValueError("DNSDB API key is missing or invalid")
    url = _dnsdb_url(query)
    parsed = urllib.parse.urlsplit(url)
    expected_path = DNSDB_PATH + urllib.parse.quote(query, safe="*.-")
    if parsed.scheme != "https" or parsed.hostname != DNSDB_HOST or parsed.path != expected_path or parsed.port is not None:
        raise ValueError("DNSDB provider URL failed fixed-origin validation")
    client = opener or urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers={
        "Accept": "application/x-ndjson", "X-API-Key": api_key,
        "User-Agent": "SNAKE-passive-collector/1.0",
    }, method="GET")
    with client.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        if response.status != 200:
            raise ValueError("DNSDB provider returned a non-200 response")
        raw = response.read(DNSDB_MAX_RESPONSE_BYTES + 1)
    if len(raw) > DNSDB_MAX_RESPONSE_BYTES:
        raise ValueError("DNSDB provider response exceeds 1 MiB")
    try:
        messages = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("DNSDB provider returned invalid JSONL") from exc
    if not messages or messages[0] != {"cond": "begin"}:
        raise ValueError("DNSDB response is missing SAF begin frame")
    terminal = messages[-1]
    if not isinstance(terminal, dict) or terminal.get("cond") not in {"succeeded", "limited"}:
        raise ValueError("DNSDB response is incomplete or unsuccessful")
    rows: list[dict[str, Any]] = []
    for message in messages[1:-1]:
        if not isinstance(message, dict) or set(message) != {"obj"} or not isinstance(message["obj"], dict):
            raise ValueError("DNSDB response contains an invalid SAF object frame")
        rows.append(message["obj"])
        if len(rows) > DNSDB_MAX_ROWS:
            raise ValueError("DNSDB response exceeds 2000 records")
    return rows, str(terminal["cond"])


def collect_dnsdb_feed(
    scope_rules: list[str], api_key: str, *, fetcher=fetch_dnsdb_rows
) -> list[dict[str, str]]:
    """Collect passive DNS RRsets; never resolve discovered names."""
    policy = ScopePolicy(scope_rules)
    queries = list(dict.fromkeys(
        ("*." + rule[2:]) if rule.startswith("*.") else rule for rule in scope_rules
    ))
    records: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    fetched_at = datetime.now(timezone.utc).isoformat()
    for query in queries:
        rows, completion = fetcher(query, api_key)
        for row in rows:
            if not isinstance(row, dict):
                continue
            rrname, rrtype, rdata = row.get("rrname"), row.get("rrtype"), row.get("rdata")
            timestamp = row.get("time_last") or row.get("time_first")
            if not isinstance(rrname, str) or not isinstance(rrtype, str):
                continue
            if not re.fullmatch(r"[A-Z0-9-]{1,16}", rrtype.upper()):
                continue
            # Zone-file imports are not passive DNS replication observations.
            if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
                continue
            if not isinstance(rdata, list) or not rdata or len(rdata) > 32:
                continue
            try:
                host = normalize_host(rrname.rstrip("."))
                observed_at = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                continue
            if not policy.check_url("https://" + host).allowed:
                continue
            for datum in rdata:
                if not isinstance(datum, str) or not datum or len(datum) > 2048:
                    continue
                if any(ord(ch) < 32 or ord(ch) == 127 for ch in datum):
                    continue
                key = (host, rrtype.upper(), datum, observed_at)
                if key in seen:
                    continue
                seen.add(key)
                evidence = (
                    f"hostname={host}; provider=dnsdb; rrtype={rrtype.upper()}; "
                    f"rdata={datum}; fetched_at={fetched_at}; completion={completion}"
                )
                records.append({
                    "hostname": host, "kind": "dns_record",
                    "value": f"{rrtype.upper()} {datum}",
                    "evidence": evidence[:8000], "source": "dnsdb_passive_dns",
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
    parser = argparse.ArgumentParser(description="Collect passive DNS intelligence for an operator-reviewed scope")
    parser.add_argument("--scope-file", required=True, help="JSON file containing approved_scope_rules")
    parser.add_argument("--output", required=True, help="private JSON feed output path")
    parser.add_argument("--provider", action="append", choices=["ct", "dnsdb"],
                        help="passive source to query; repeat to combine providers (default: ct)")
    parser.add_argument("--authorization-reference", required=True,
                        help="operator's audit reference; this is not independently verified")
    args = parser.parse_args()
    if not args.authorization_reference.strip() or len(args.authorization_reference) > 200:
        parser.error("authorization reference must be 1-200 characters")
    rules = load_scope(args.scope_file)
    providers = list(dict.fromkeys(args.provider or ["ct"]))
    records: list[dict[str, str]] = []
    per_provider_limit = MAX_FEED_RECORDS if len(providers) == 1 else MAX_FEED_RECORDS // len(providers)
    if "ct" in providers:
        records.extend(collect_ct_feed(rules)[:per_provider_limit])
    if "dnsdb" in providers:
        api_key = os.environ.get("DNSDB_API_KEY", "")
        if not api_key:
            parser.error("DNSDB_API_KEY environment variable is required for --provider dnsdb")
        records.extend(collect_dnsdb_feed(rules, api_key)[:per_provider_limit])
    records = records[:MAX_FEED_RECORDS]
    write_feed(args.output, records)
    print(json.dumps({
        "providers": providers, "records": len(records),
        "scope_rules": len(rules), "authorization_reference": args.authorization_reference,
        "feed": str(args.output), "execution_enabled": False,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
