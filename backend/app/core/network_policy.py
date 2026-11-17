"""Network destination policy for future workers.

This module performs DNS resolution only; it never opens an HTTP connection.
Call it immediately before dispatch and again immediately before each request.
The returned addresses are the only addresses a worker may connect to (pinning).
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlsplit

from app.core.scope_policy import ScopePolicy, normalize_host


class NetworkPolicyError(ValueError):
    """A destination cannot safely be used by a scanner worker."""


@dataclass(frozen=True)
class ResolvedDestination:
    hostname: str
    port: int
    addresses: tuple[str, ...]


Resolver = Callable[[str, int], Iterable[str]]


def _system_resolver(hostname: str, port: int) -> Iterable[str]:
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise NetworkPolicyError("dns_resolution_failed") from exc
    return (record[4][0] for record in records)


def _public_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError as exc:
        raise NetworkPolicyError("resolver_returned_invalid_ip") from exc
    # IPv4-mapped IPv6 is normalized before classification.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not address.is_global or address.is_multicast or address.is_unspecified:
        raise NetworkPolicyError("non_public_ip_address")
    return address


def resolve_public_destination(
    url: str,
    allowlist: list[str],
    resolver: Resolver = _system_resolver,
) -> ResolvedDestination:
    """Validate scope, resolve the host, and reject the entire answer if any IP is unsafe."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise NetworkPolicyError("unsupported_scheme")
        if not parsed.hostname:
            raise NetworkPolicyError("missing_hostname")
        if parsed.username is not None or parsed.password is not None:
            raise NetworkPolicyError("embedded_credentials_not_allowed")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        hostname = normalize_host(parsed.hostname)
    except NetworkPolicyError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise NetworkPolicyError("invalid_url_or_hostname") from exc

    decision = ScopePolicy(allowlist).check_url(url)
    if not decision.allowed:
        raise NetworkPolicyError("out_of_scope")

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        raw_addresses = resolver(hostname, port)
    else:
        raw_addresses = [str(literal)]

    addresses = set()
    for raw in raw_addresses:
        addresses.add(str(_public_ip(str(raw))))
    if not addresses:
        raise NetworkPolicyError("dns_no_addresses")
    return ResolvedDestination(hostname, port, tuple(sorted(addresses)))


def validate_redirect_chain(
    initial_url: str,
    redirect_urls: Iterable[str],
    allowlist: list[str],
    resolver: Resolver = _system_resolver,
) -> tuple[ResolvedDestination, ...]:
    """Revalidate every hop; callers must connect only to each hop's pinned addresses."""
    destinations = [resolve_public_destination(initial_url, allowlist, resolver)]
    for url in redirect_urls:
        destinations.append(resolve_public_destination(url, allowlist, resolver))
    return tuple(destinations)
