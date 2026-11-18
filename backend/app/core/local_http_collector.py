"""Low-impact, bounded HTTP collection for explicitly approved local recon.

Only GET requests are issued. Every redirect is revalidated against the
approved hostname allowlist and DNS is resolved again before connecting.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from app.core.scope_policy import ScopePolicy


MAX_BODY_BYTES = 256 * 1024
MAX_PAGES = 10
MAX_REDIRECTS = 3
REQUEST_TIMEOUT_SECONDS = 5.0
USER_AGENT = "SNAKE-Local-Recon/0.1"


class CollectionError(ValueError):
    """A request was refused or could not be collected safely."""


@dataclass(frozen=True)
class HttpObservation:
    url: str
    status_code: int
    content_type: str
    body_bytes: int
    headers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class CollectionReport:
    observations: tuple[HttpObservation, ...]
    skipped: tuple[tuple[str, str], ...]
    pages_requested: int
    body_limit_bytes: int


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() not in {"a", "link", "script", "img", "form"}:
            return
        for key, value in attrs:
            if key.lower() == "href" or (tag.lower() in {"script", "img"} and key.lower() == "src"):
                if value and len(self.hrefs) < 100:
                    self.hrefs.append(value)


def _resolve_public(host: str, port: int, *, allow_private_networks: bool = False) -> list[tuple]:
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise CollectionError("dns_resolution_failed") from exc
    if not answers:
        raise CollectionError("dns_no_addresses")
    pinned: list[tuple] = []
    seen: set[str] = set()
    for family, socktype, proto, _canonname, sockaddr in answers:
        address = sockaddr[0]
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise CollectionError("dns_returned_invalid_address") from exc
        if not allow_private_networks and not ip.is_global:
            raise CollectionError("dns_resolved_to_non_public_address")
        normalized = str(ip)
        if normalized not in seen:
            pinned.append((family, socktype, proto, sockaddr))
            seen.add(normalized)
    return pinned


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, sockaddr: tuple, timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._sockaddr = sockaddr

    def connect(self) -> None:
        family, socktype, proto, sockaddr = self._sockaddr
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(self.timeout)
        try:
            sock.connect(sockaddr)
        except Exception:
            sock.close()
            raise
        self.sock = sock


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    def __init__(self, host: str, port: int, sockaddr: tuple, timeout: float):
        super().__init__(host, port, sockaddr, timeout)
        self._context = ssl.create_default_context()

    def connect(self) -> None:
        super().connect()
        assert self.sock is not None
        try:
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
        except Exception:
            self.close()
            raise


def _safe_url(url: str, policy: ScopePolicy) -> tuple[str, str, int, str]:
    decision = policy.check_url(url)
    if not decision.allowed or not decision.hostname:
        raise CollectionError("url_out_of_scope")
    parsed = urlsplit(url)
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
    scheme = parsed.scheme.lower()
    host = decision.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    if len(path) > 2048:
        raise CollectionError("request_path_too_long")
    normalized = urlunsplit((scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    return normalized, host, port, path


def _request_once(url: str, policy: ScopePolicy, *, timeout: float,
                  max_body_bytes: int, allow_private_networks: bool) -> tuple[HttpObservation, bytes, str | None]:
    normalized, host, port, path = _safe_url(url, policy)
    parsed = urlsplit(normalized)
    addresses = _resolve_public(host, port, allow_private_networks=allow_private_networks)
    last_error: Exception | None = None
    for sockaddr in addresses:
        connection: http.client.HTTPConnection
        if parsed.scheme == "https":
            connection = _PinnedHTTPSConnection(host, port, sockaddr, timeout)
        else:
            connection = _PinnedHTTPConnection(host, port, sockaddr, timeout)
        try:
            connection.connect()
            host_header = f"[{host}]" if ":" in host else host
            if port not in (80, 443):
                host_header += f":{port}"
            connection.putrequest("GET", path, skip_accept_encoding=True)
            connection.putheader("Host", host_header)
            connection.putheader("User-Agent", USER_AGENT)
            connection.putheader("Accept", "text/html,application/json,text/plain,*/*;q=0.1")
            connection.putheader("Accept-Encoding", "identity")
            connection.putheader("Connection", "close")
            connection.endheaders()
            response = connection.getresponse()
            body = response.read(max_body_bytes + 1)
            if len(body) > max_body_bytes:
                body = body[:max_body_bytes]
                truncated = True
            else:
                truncated = False
            headers = tuple(
                (name.lower(), value[:2048])
                for name, value in response.getheaders()
                if name.lower() in {
                    "server", "x-powered-by", "x-aspnet-version", "x-generator",
                    "access-control-allow-origin", "access-control-allow-credentials",
                    "set-cookie", "content-type", "content-length", "location",
                    "strict-transport-security", "content-security-policy",
                }
            )
            content_type = next((v for k, v in headers if k == "content-type"), "")
            location = next((v for k, v in headers if k == "location"), None)
            observation = HttpObservation(
                url=normalized,
                status_code=response.status,
                content_type=content_type[:200],
                body_bytes=min(len(body), max_body_bytes),
                headers=headers,
            )
            return observation, body[:max_body_bytes], location
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            last_error = exc
        finally:
            connection.close()
    raise CollectionError("http_request_failed") from last_error


def collect_http(
    target_url: str,
    approved_scope_rules: list[str],
    *,
    max_pages: int = MAX_PAGES,
    max_body_bytes: int = MAX_BODY_BYTES,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
    allow_private_networks: bool = False,
) -> CollectionReport:
    """Collect a small same-host link graph without retaining response bodies."""
    if not 1 <= max_pages <= MAX_PAGES:
        raise ValueError(f"max_pages must be between 1 and {MAX_PAGES}")
    if not 1024 <= max_body_bytes <= MAX_BODY_BYTES:
        raise ValueError(f"max_body_bytes must be between 1024 and {MAX_BODY_BYTES}")
    if not 1 <= timeout <= 10:
        raise ValueError("timeout must be between 1 and 10 seconds")
    policy = ScopePolicy(approved_scope_rules)
    initial, initial_host, _port, _path = _safe_url(target_url, policy)
    queue = [initial]
    visited: set[str] = set()
    observations: list[HttpObservation] = []
    skipped: list[tuple[str, str]] = []

    while queue and len(observations) < max_pages:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        try:
            observation, body, location = _request_once(
                current, policy, timeout=timeout, max_body_bytes=max_body_bytes,
                allow_private_networks=allow_private_networks,
            )
        except CollectionError as exc:
            skipped.append((current, str(exc)))
            continue
        observations.append(observation)

        if location and observation.status_code in {301, 302, 303, 307, 308}:
            redirect = urljoin(current, location)
            try:
                _normalized, redirect_host, _p, _path = _safe_url(redirect, policy)
                if redirect_host != initial_host:
                    skipped.append((redirect, "cross_host_redirect_skipped"))
                elif len(visited) <= MAX_REDIRECTS:
                    queue.insert(0, redirect)
                else:
                    skipped.append((redirect, "redirect_limit_reached"))
            except CollectionError as exc:
                skipped.append((redirect, str(exc)))
            continue

        if "html" in observation.content_type.lower() and body:
            parser = _Links()
            try:
                parser.feed(body.decode("utf-8", errors="replace"))
            except Exception:
                parser.close()
            for href in parser.hrefs:
                candidate = urljoin(current, href)
                try:
                    normalized, candidate_host, _p, _path = _safe_url(candidate, policy)
                except CollectionError:
                    continue
                parsed_candidate = urlsplit(normalized)
                parsed_initial = urlsplit(initial)
                if (
                    candidate_host == initial_host
                    and parsed_candidate.scheme == parsed_initial.scheme
                    and normalized not in visited
                    and normalized not in queue
                    and len(visited) + len(queue) < max_pages
                ):
                    queue.append(normalized)

    return CollectionReport(
        observations=tuple(observations),
        skipped=tuple(skipped),
        pages_requested=len(observations),
        body_limit_bytes=max_body_bytes,
    )
