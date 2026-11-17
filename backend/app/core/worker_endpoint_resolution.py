"""Resolve registered worker endpoints to validated, pin-ready public addresses.

This module performs DNS only. It never opens a socket. A future HTTP transport
must connect to one of the returned IPs directly (not re-resolve the hostname),
while retaining the registered TLS server name and verifying the certificate pin.
"""
from sqlalchemy.orm import Session

from app.core.network_policy import ResolvedDestination, Resolver, resolve_public_destination
from app.db.models import WorkerEndpoint


def resolve_registered_worker_endpoint(
    db: Session, *, worker_id: str, resolver: Resolver
) -> tuple[WorkerEndpoint, ResolvedDestination]:
    endpoint = db.query(WorkerEndpoint).filter_by(
        worker_id=worker_id, status="active"
    ).first()
    if endpoint is None:
        raise ValueError("worker endpoint is not registered and active")
    destination = resolve_public_destination(
        endpoint.base_url,
        [endpoint.tls_server_name],
        resolver,
    )
    if destination.hostname != endpoint.tls_server_name:
        raise ValueError("resolved endpoint hostname does not match registered TLS identity")
    return endpoint, destination
