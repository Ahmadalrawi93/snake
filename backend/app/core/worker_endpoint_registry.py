"""Validation and lifecycle for administratively provisioned worker endpoints."""
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from app.core.scope_policy import normalize_host
from app.db.models import WorkerEndpoint


def validate_worker_endpoint(base_url: str, tls_server_name: str, certificate_sha256: str) -> tuple[str, str, str]:
    if len(base_url) > 512:
        raise ValueError("endpoint URL is too long")
    try:
        parsed = urlsplit(base_url)
        host = normalize_host(parsed.hostname or "")
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid worker endpoint URL") from exc
    if parsed.scheme.lower() != "https":
        raise ValueError("worker endpoint must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("endpoint credentials are forbidden")
    if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("endpoint must be an origin URL without path, query, or fragment")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("worker endpoint must use a DNS hostname, not an IP literal")
    if host in {"localhost"} or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("local or internal endpoint hostname is forbidden")
    server_name = normalize_host(tls_server_name)
    if server_name != host:
        raise ValueError("TLS server name must match endpoint hostname")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", certificate_sha256):
        raise ValueError("certificate SHA-256 fingerprint must be 64 hexadecimal characters")
    authority = host if port in (None, 443) else f"{host}:{port}"
    canonical = urlunsplit(("https", authority, "", "", ""))
    return canonical, server_name, certificate_sha256.lower()


def register_worker_endpoint(
    db: Session, *, worker_id: str, base_url: str, tls_server_name: str,
    certificate_sha256: str, created_by: int | None,
) -> WorkerEndpoint:
    canonical, server_name, fingerprint = validate_worker_endpoint(
        base_url, tls_server_name, certificate_sha256
    )
    if not db.query(WorkerEndpoint).filter_by(worker_id=worker_id).first() is None:
        raise ValueError("worker endpoint already exists; revoke it before replacement")
    row = WorkerEndpoint(
        worker_id=worker_id, base_url=canonical, tls_server_name=server_name,
        certificate_sha256=fingerprint, status="active", created_by=created_by,
    )
    db.add(row)
    db.flush()
    return row


def revoke_worker_endpoint(
    db: Session, *, worker_id: str, now: datetime | None = None
) -> WorkerEndpoint | None:
    row = db.query(WorkerEndpoint).filter_by(worker_id=worker_id).first()
    if row is None:
        return None
    if row.status != "active":
        raise ValueError("worker endpoint is already revoked")
    row.status = "revoked"
    row.revoked_at = now or datetime.now(timezone.utc)
    db.flush()
    return row
