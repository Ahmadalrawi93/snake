"""Minimal mTLS HTTPS listener for validation-only worker tasks.

This server acknowledges authenticated task envelopes. It has no scan executor,
shell interface, database, queue, or target-network access.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
from threading import BoundedSemaphore
import ssl

from pydantic import ValidationError

from worker_replay_ledger import WorkerReplayLedger

from app.core.worker_protocol import WorkerValidationResult, ensure_not_expired
from worker_passive_recon import build_signed_passive_batch, read_passive_feed
from app.schemas.worker_transport import WorkerTaskResponse
from app.core.worker_signing import (
    SignedWorkerTask,
    sign_worker_validation_result,
    verify_worker_task,
    worker_task_digest,
)

TASK_PATH = "/internal/v1/tasks"
MAX_BODY_BYTES = 64 * 1024


def worker_bind_config(environ=None) -> tuple[str, int]:
    """Resolve a fail-closed listener address; public wildcard binds are forbidden."""
    values = os.environ if environ is None else environ
    host = values.get("SNAKE_WORKER_BIND_HOST", "127.0.0.1")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("worker bind host must be an explicit IP address") from exc
    if address.is_unspecified:
        raise ValueError("worker listener must not bind to a wildcard address")
    try:
        port = int(values.get("SNAKE_WORKER_BIND_PORT", "8443"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid worker bind port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("invalid worker bind port")
    return str(address), port


def validate_http_task_headers(headers) -> tuple[int, int | None]:
    """Validate framing headers before reading a task body.

    Reject ambiguous framing instead of relying on email.message's combined
    duplicate-header behavior. Expect/continue is unsupported deliberately.
    """
    for name in ("Content-Length", "Content-Type", "Host"):
        values = headers.get_all(name, [])
        if len(values) > 1:
            return 400, None
    hosts = headers.get_all("Host", [])
    if len(hosts) != 1:
        return 400, None
    host = hosts[0].strip()
    if (not host or not host.isascii()
            or any(ord(char) <= 32 or ord(char) == 127 for char in host)
            or "," in host):
        return 400, None
    if (headers.get_all("Transfer-Encoding", [])
            or headers.get_all("Content-Encoding", [])
            or headers.get_all("Trailer", [])
            or headers.get_all("Upgrade", [])):
        return 400, None
    if headers.get_all("Expect", []):
        return 417, None
    content_types = headers.get_all("Content-Type", [])
    if len(content_types) != 1 or content_types[0].strip().lower() != "application/json":
        return 415, None
    lengths = headers.get_all("Content-Length", [])
    if not lengths:
        return 411, None
    raw_length = lengths[0].strip()
    if not raw_length.isascii() or not raw_length.isdecimal():
        return 400, None
    length = int(raw_length)
    if length < 1 or length > MAX_BODY_BYTES:
        return 413, None
    return 200, length


def validate_task_request(raw: bytes, *, backend_public_key: str,
                          worker_private_key: str, worker_id: str,
                          key_id: str, replay_ledger: WorkerReplayLedger | None = None,
                          passive_feed_path: str | None = None) -> bytes:
    """Return a durable, signed validation-only acknowledgement."""
    if not raw or len(raw) > MAX_BODY_BYTES:
        raise ValueError("invalid task body size")
    signed = SignedWorkerTask.model_validate_json(raw)
    if not verify_worker_task(
        signed, backend_public_key,
        expected_worker_id=worker_id, expected_key_id=key_id,
    ):
        raise ValueError("task_signature_or_worker_binding_invalid")
    digest = worker_task_digest(signed.envelope)

    def create_acknowledgement() -> bytes:
        result = WorkerValidationResult(
            task_id=signed.envelope.task_id,
            envelope_sha256=digest,
            worker_id=worker_id,
            outcome="accepted",
            validated_at=datetime.now(timezone.utc),
            execution_enabled=False,
        )
        acknowledgement = sign_worker_validation_result(
            result, worker_private_key, key_id=key_id
        )
        observation_batch = None
        if passive_feed_path:
            records = read_passive_feed(passive_feed_path)
            observation_batch = build_signed_passive_batch(
                signed.envelope, records, worker_id=worker_id, key_id=key_id,
                worker_private_key_b64=worker_private_key,
            )
        return WorkerTaskResponse(
            acknowledgement=acknowledgement,
            observation_batch=observation_batch,
        ).model_dump_json().encode("utf-8")

    if replay_ledger is None:
        ensure_not_expired(signed.envelope)
        return create_acknowledgement()

    acknowledgement, _duplicate = replay_ledger.get_or_create(
        task_id=str(signed.envelope.task_id),
        envelope_sha256=digest,
        worker_id=worker_id,
        key_id=key_id,
        create_acknowledgement=create_acknowledgement,
        validate_first_acceptance=lambda: ensure_not_expired(signed.envelope),
    )
    return acknowledgement


class _ThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_slots = BoundedSemaphore(16)
    expected_client_certificate_sha256: str | None = None

    def get_request(self):
        request, client_address = super().get_request()
        try:
            request.settimeout(5.0)
            request.do_handshake()
            peer_certificate = request.getpeercert(binary_form=True)
            expected = self.expected_client_certificate_sha256
            actual = hashlib.sha256(peer_certificate).hexdigest() if peer_certificate else ""
            if not expected or actual != expected:
                raise ssl.SSLError("backend_client_certificate_pin_mismatch")
            return request, client_address
        except Exception:
            request.close()
            raise

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


def build_handler(*, backend_public_key: str, worker_private_key: str,
                  worker_id: str, key_id: str,
                  replay_ledger: WorkerReplayLedger | None = None,
                  passive_feed_path: str | None = None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SNAKE-Worker"
        sys_version = ""

        def setup(self):
            self.request.settimeout(5.0)
            super().setup()

        def log_message(self, fmt, *args):
            # Avoid logging task payloads or credential-bearing headers.
            return

        def _send(self, status: int, body: bytes):
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                # A peer may close after sending a request (for example, on a
                # client timeout). Do not leak a handler traceback at shutdown.
                pass
            finally:
                self.close_connection = True

        def do_POST(self):
            # The backend adapter emits HTTP/1.1. Reject legacy/unknown
            # versions rather than applying ambiguous framing semantics.
            if self.request_version != "HTTP/1.1":
                self._send(505, b'{"error":"http_version_not_supported"}')
                return
            if self.path != TASK_PATH:
                self._send(404, b'{"error":"not_found"}')
                return
            header_status, length = validate_http_task_headers(self.headers)
            if header_status != 200:
                errors = {
                    400: b'{"error":"ambiguous_or_invalid_headers"}',
                    411: b'{"error":"content_length_required"}',
                    413: b'{"error":"request_too_large"}',
                    415: b'{"error":"application_json_required"}',
                    417: b'{"error":"expectation_not_supported"}',
                }
                self._send(header_status, errors[header_status])
                return
            assert length is not None
            raw = self.rfile.read(length)
            if len(raw) != length:
                self._send(400, b'{"error":"incomplete_request_body"}')
                return
            try:
                response = validate_task_request(
                    raw,
                    backend_public_key=backend_public_key,
                    worker_private_key=worker_private_key,
                    worker_id=worker_id,
                    key_id=key_id,
                    replay_ledger=replay_ledger,
                    passive_feed_path=passive_feed_path,
                )
            except (ValidationError, ValueError):
                self._send(400, b'{"error":"task_rejected"}')
                return
            self._send(200, response)

        def do_GET(self):
            self._send(405, b'{"error":"method_not_allowed"}')

    return Handler


def serve() -> None:
    cert = os.environ["SNAKE_WORKER_TLS_CERT_FILE"]
    key = os.environ["SNAKE_WORKER_TLS_KEY_FILE"]
    client_ca = os.environ["SNAKE_BACKEND_CLIENT_CA_FILE"]
    client_fingerprint = os.environ["SNAKE_BACKEND_CLIENT_CERT_SHA256"].lower()
    if len(client_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in client_fingerprint):
        raise ValueError("invalid backend client certificate SHA-256 fingerprint")
    backend_public = os.environ["SNAKE_BACKEND_ED25519_PUBLIC_KEY_B64"]
    worker_private = os.environ["SNAKE_WORKER_ED25519_PRIVATE_KEY_B64"]
    worker_id = os.environ["SNAKE_WORKER_ID"]
    key_id = os.environ["SNAKE_WORKER_KEY_ID"]
    ledger_path = os.environ["SNAKE_WORKER_REPLAY_DB_PATH"]
    replay_ledger = WorkerReplayLedger(ledger_path)
    passive_feed_path = os.environ.get("SNAKE_WORKER_PASSIVE_FEED_FILE") or None
    host, port = worker_bind_config()

    server = _ThreadingHTTPServer((host, port), build_handler(
        backend_public_key=backend_public,
        worker_private_key=worker_private,
        worker_id=worker_id,
        key_id=key_id,
        replay_ledger=replay_ledger,
        passive_feed_path=passive_feed_path,
    ))
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=cert, keyfile=key)
    context.load_verify_locations(cafile=client_ca)
    server.expected_client_certificate_sha256 = client_fingerprint
    server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
