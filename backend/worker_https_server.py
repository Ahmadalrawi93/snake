"""Minimal mTLS HTTPS listener for validation-only worker tasks.

This server acknowledges authenticated task envelopes. It has no scan executor,
shell interface, database, queue, or target-network access.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
from socketserver import ThreadingMixIn
from threading import BoundedSemaphore
import ssl

from pydantic import ValidationError

from app.core.worker_protocol import WorkerValidationResult, ensure_not_expired
from app.core.worker_signing import (
    SignedWorkerTask,
    sign_worker_validation_result,
    verify_worker_task,
    worker_task_digest,
)

TASK_PATH = "/internal/v1/tasks"
MAX_BODY_BYTES = 64 * 1024


def validate_task_request(raw: bytes, *, backend_public_key: str,
                          worker_private_key: str, worker_id: str,
                          key_id: str) -> bytes:
    """Return a signed validation-only acknowledgement for one authenticated task."""
    if not raw or len(raw) > MAX_BODY_BYTES:
        raise ValueError("invalid_task_body_size")
    signed = SignedWorkerTask.model_validate_json(raw)
    if not verify_worker_task(
        signed, backend_public_key,
        expected_worker_id=worker_id, expected_key_id=key_id,
    ):
        raise ValueError("task_signature_or_worker_binding_invalid")
    ensure_not_expired(signed.envelope)
    result = WorkerValidationResult(
        task_id=signed.envelope.task_id,
        envelope_sha256=worker_task_digest(signed.envelope),
        worker_id=worker_id,
        outcome="accepted",
        validated_at=datetime.now(timezone.utc),
        execution_enabled=False,
    )
    return sign_worker_validation_result(
        result, worker_private_key, key_id=key_id
    ).model_dump_json().encode("utf-8")


class _ThreadingHTTPServer(ThreadingMixIn, ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_slots = BoundedSemaphore(16)

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
                  worker_id: str, key_id: str):
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
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_POST(self):
            if self.path != TASK_PATH:
                self._send(404, b'{"error":"not_found"}')
                return
            if self.headers.get("Transfer-Encoding") is not None:
                self._send(400, b'{"error":"transfer_encoding_not_supported"}')
                return
            if self.headers.get_content_type() != "application/json":
                self._send(415, b'{"error":"application_json_required"}')
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send(411, b'{"error":"content_length_required"}')
                return
            if length < 1 or length > MAX_BODY_BYTES:
                self._send(413, b'{"error":"request_too_large"}')
                return
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
    backend_public = os.environ["SNAKE_BACKEND_ED25519_PUBLIC_KEY_B64"]
    worker_private = os.environ["SNAKE_WORKER_ED25519_PRIVATE_KEY_B64"]
    worker_id = os.environ["SNAKE_WORKER_ID"]
    key_id = os.environ["SNAKE_WORKER_KEY_ID"]
    host = os.environ.get("SNAKE_WORKER_BIND_HOST", "0.0.0.0")
    port = int(os.environ.get("SNAKE_WORKER_BIND_PORT", "8443"))
    if not 1 <= port <= 65535:
        raise ValueError("invalid worker bind port")

    server = _ThreadingHTTPServer((host, port), build_handler(
        backend_public_key=backend_public,
        worker_private_key=worker_private,
        worker_id=worker_id,
        key_id=key_id,
    ))
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=cert, keyfile=key)
    context.load_verify_locations(cafile=client_ca)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
