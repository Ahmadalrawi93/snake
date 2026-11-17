"""Pinned-IP, certificate-pinned mTLS dispatch adapter.

This module is an internal primitive, not an API route or background worker.
It sends only already-signed task envelopes and never enables scan execution.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
from datetime import datetime
from typing import Callable

from sqlalchemy.orm import Session

from app.core.network_policy import Resolver
from app.core.worker_acknowledgements import accept_worker_acknowledgement
from app.core.worker_dispatch_attempts import begin_dispatch_attempt, finish_dispatch_attempt
from app.core.worker_endpoint_resolution import resolve_registered_worker_endpoint
from app.core.worker_signing import (
    SignedWorkerTask, SignedWorkerValidationResult, worker_task_digest,
)
from app.db.models import WorkerEndpoint, WorkerKey, WorkerTaskReceipt


TASK_PATH = "/internal/v1/tasks"
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 64 * 1024


class WorkerTransportError(RuntimeError):
    pass


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a validated IP but retains DNS TLS identity."""

    def __init__(
        self, *, pinned_ip: str, hostname: str, port: int,
        context: ssl.SSLContext, timeout: float,
        expected_fingerprint: str,
    ):
        super().__init__(hostname, port=port, context=context, timeout=timeout)
        self._pinned_ip = pinned_ip
        self._expected_fingerprint = expected_fingerprint.lower()

    def connect(self):
        raw = socket.create_connection(
            (self._pinned_ip, self.port), timeout=self.timeout
        )
        try:
            tls_socket = self._context.wrap_socket(
                raw, server_hostname=self.host
            )
            actual = hashlib.sha256(tls_socket.getpeercert(binary_form=True)).hexdigest()
            if actual != self._expected_fingerprint:
                tls_socket.close()
                raise WorkerTransportError("worker_tls_certificate_pin_mismatch")
            self.sock = tls_socket
        except Exception:
            raw.close()
            raise


def _build_mtls_context(
    client_certificate_path: str, client_private_key_path: str,
    ca_certificate_path: str,
) -> ssl.SSLContext:
    if not client_certificate_path or not client_private_key_path or not ca_certificate_path:
        raise ValueError("mTLS client certificate, private key, and CA certificate paths are required")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(
        certfile=client_certificate_path,
        keyfile=client_private_key_path,
    )
    context.load_verify_locations(cafile=ca_certificate_path)
    return context


def deliver_signed_worker_task(
    db: Session,
    signed_task: SignedWorkerTask,
    *,
    resolver: Resolver,
    client_certificate_path: str,
    client_private_key_path: str,
    ca_certificate_path: str,
    now: datetime | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
    connection_factory: Callable[..., http.client.HTTPSConnection] = _PinnedHTTPSConnection,
) -> dict:
    """Deliver one task over mTLS to an admin-registered endpoint.

    DNS is resolved and validated before the attempt is committed. A connection
    uses exactly one validated IP and the registered TLS name. Once request
    transmission starts, any ambiguous exception is recorded as unknown, never
    automatically retried. This function does not execute scans or accept results.
    """
    if not 0.1 <= timeout_seconds <= 30:
        raise ValueError("timeout_seconds must be between 0.1 and 30")
    if not 1024 <= max_response_bytes <= MAX_RESPONSE_BYTES:
        raise ValueError("max_response_bytes is outside the allowed range")

    worker_id, key_id = signed_task.worker_id, signed_task.key_id
    endpoint, destination = resolve_registered_worker_endpoint(
        db, worker_id=worker_id, resolver=resolver
    )
    key = db.query(WorkerKey).filter_by(
        worker_id=worker_id, key_id=key_id, status="active"
    ).first()
    if key is None:
        raise ValueError("worker key is not registered and active")
    receipt = db.query(WorkerTaskReceipt).filter_by(
        task_id=str(signed_task.envelope.task_id)
    ).first()
    if receipt is None:
        raise ValueError("signed task receipt not found")
    digest = worker_task_digest(signed_task.envelope)
    if receipt.envelope_sha256 != digest:
        raise ValueError("signed task digest does not match receipt")
    if receipt.worker_id != worker_id or receipt.key_id != key_id:
        raise ValueError("signed task worker identity does not match receipt")

    # Validate local mTLS material and construct the connection object before
    # reserving an attempt. The constructor performs no network I/O.
    context = _build_mtls_context(
        client_certificate_path, client_private_key_path, ca_certificate_path
    )
    address = destination.addresses[0]
    connection = connection_factory(
        pinned_ip=address,
        hostname=endpoint.tls_server_name,
        port=destination.port,
        context=context,
        timeout=timeout_seconds,
        expected_fingerprint=endpoint.certificate_sha256,
    )

    attempt = begin_dispatch_attempt(
        db,
        task_id=signed_task.envelope.task_id,
        worker_id=worker_id,
        key_id=key_id,
        envelope_sha256=digest,
        now=now,
    )

    # Re-read endpoint immediately before the first network operation.
    current_endpoint = db.query(WorkerEndpoint).filter_by(
        worker_id=worker_id, status="active"
    ).first()
    current_key = db.query(WorkerKey).filter_by(
        worker_id=worker_id, key_id=key_id, status="active"
    ).first()
    if current_key is None or current_endpoint is None or (
        current_endpoint.id != endpoint.id
        or current_endpoint.certificate_sha256 != endpoint.certificate_sha256
        or current_endpoint.base_url != endpoint.base_url
    ):
        finish_dispatch_attempt(
            db, attempt.id, "failed", error_code="endpoint_changed_before_connect", now=now
        )
        connection.close()
        raise ValueError("worker endpoint changed before connection")

    host_header = endpoint.tls_server_name
    if destination.port != 443:
        host_header = f"{host_header}:{destination.port}"
    body = signed_task.model_dump_json().encode("utf-8")
    request_started = False
    try:
        request_started = True
        connection.request(
            "POST",
            TASK_PATH,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Host": host_header,
                "Content-Length": str(len(body)),
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        payload = response.read(max_response_bytes + 1)
        if len(payload) > max_response_bytes:
            finish_dispatch_attempt(
                db, attempt.id, "unknown", error_code="response_too_large", now=now
            )
            raise WorkerTransportError("worker_response_too_large")
        if response.status not in (200, 202):
            finish_dispatch_attempt(
                db, attempt.id, "unknown",
                error_code=f"http_status_{response.status}", now=now
            )
            raise WorkerTransportError(f"worker_http_status_{response.status}")
        try:
            signed_ack = SignedWorkerValidationResult.model_validate_json(payload)
        except Exception as exc:
            finish_dispatch_attempt(
                db, attempt.id, "unknown", error_code="invalid_signed_acknowledgement", now=now
            )
            raise WorkerTransportError("worker_response_is_not_a_valid_signed_acknowledgement") from exc
        accepted = accept_worker_acknowledgement(
            db, signed_ack,
            expected_worker_id=worker_id,
            expected_key_id=key_id,
            now=now,
        )
        if not accepted:
            finish_dispatch_attempt(
                db, attempt.id, "unknown", error_code="acknowledgement_rejected", now=now
            )
            raise WorkerTransportError("worker_acknowledgement_verification_failed")
        finish_dispatch_attempt(db, attempt.id, "delivered", now=now)
        return {
            "task_id": str(signed_task.envelope.task_id),
            "worker_id": worker_id,
            "attempt_id": attempt.id,
            "http_status": response.status,
            "acknowledgement": signed_ack.model_dump(mode="json"),
        }
    except Exception as exc:
        # A failure before a request is attempted is definite; after transmission
        # begins it may have reached the worker, so preserve the unknown outcome.
        try:
            finish_dispatch_attempt(
                db, attempt.id,
                "unknown" if request_started else "failed",
                error_code="transport_exception",
                now=now,
            )
        except Exception:
            db.rollback()
        raise
    finally:
        connection.close()
