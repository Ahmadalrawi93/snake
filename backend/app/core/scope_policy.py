"""Deterministic hostname allowlist policy. This is not proof of legal authorization."""
from dataclasses import dataclass
from urllib.parse import urlsplit
import ipaddress
import re


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.?$")


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    hostname: str | None
    reason: str


def normalize_host(host: str) -> str:
    value = host.strip().lower().rstrip(".")
    if not value:
        raise ValueError("Invalid hostname")
    # Parse IP literals before hostname delimiter checks so bracket-stripped IPv6
    # URL hosts are supported and normalized by ipaddress.
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if any(ch in value for ch in "/\\@:#"):
        raise ValueError("Invalid hostname")
    if not _HOST_RE.fullmatch(value):
        raise ValueError("Invalid hostname")
    return value


def host_matches(host: str, pattern: str) -> bool:
    """Exact match, or *.example.com matching subdomains but not example.com itself."""
    candidate = normalize_host(host)
    rule = pattern.strip().lower()
    if rule.startswith("*."):
        suffix = normalize_host(rule[2:])
        return candidate.endswith("." + suffix)
    return candidate == normalize_host(rule)


class ScopePolicy:
    def __init__(self, allowlist: list[str]):
        self.allowlist = tuple(item for item in allowlist if item)

    def check_url(self, url: str) -> ScopeDecision:
        try:
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"}:
                return ScopeDecision(False, None, "unsupported_scheme")
            if not parsed.hostname:
                return ScopeDecision(False, None, "missing_hostname")
            host = normalize_host(parsed.hostname)
            # Accessing .port forces urllib to reject malformed or out-of-range ports.
            _ = parsed.port
            # Reject credentials embedded in URLs; they are not needed for target identity.
            if parsed.username is not None or parsed.password is not None:
                return ScopeDecision(False, host, "embedded_credentials_not_allowed")
        except (ValueError, UnicodeError):
            return ScopeDecision(False, None, "invalid_url_or_hostname")

        for rule in self.allowlist:
            try:
                if host_matches(host, rule):
                    return ScopeDecision(True, host, "allowlist_match")
            except ValueError:
                continue
        return ScopeDecision(False, host, "not_in_allowlist")
