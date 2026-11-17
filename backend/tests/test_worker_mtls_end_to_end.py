import base64
import hashlib
import http.client
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.worker_mtls_transport import (
    _PinnedHTTPSConnection,
    deliver_signed_worker_task,
)
from app.core.worker_protocol import WorkerTaskEnvelope
from app.core.worker_signing import sign_worker_task, worker_task_digest
from app.db.models import (
    ScanJob, WorkerTaskReceipt, WorkerKey, WorkerEndpoint, WorkerDispatchAttempt,
)
from worker_https_server import _ThreadingHTTPServer, build_handler


def _ed_pair():
    key = ed25519.Ed25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )).decode()
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    return private, public


def _certificates(directory: Path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SNAKE Integration CA")])
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def issue(name, public_key, usage, san=None):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
            .public_key(public_key).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        )
        if san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
            )
        return builder.sign(ca_key, hashes.SHA256())

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = issue("worker.example.org", server_key.public_key(),
                        ExtendedKeyUsageOID.SERVER_AUTH, "worker.example.org")
    client_cert = issue("snake-backend", client_key.public_key(),
                        ExtendedKeyUsageOID.CLIENT_AUTH)

    def write(name, data):
        path = directory / name
        path.write_bytes(data)
        return str(path)

    ca_path = write("ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM))
    server_cert_path = write("server.pem", server_cert.public_bytes(serialization.Encoding.PEM))
    server_key_path = write("server-key.pem", server_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    client_cert_der = client_cert.public_bytes(serialization.Encoding.DER)
    client_cert_path = write("client.pem", client_cert.public_bytes(serialization.Encoding.PEM))
    client_key_path = write("client-key.pem", client_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    server_fingerprint = hashlib.sha256(
        server_cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    client_fingerprint = hashlib.sha256(client_cert_der).hexdigest()
    return (ca_path, server_cert_path, server_key_path, client_cert_path,
            client_key_path, server_fingerprint, client_fingerprint)


class _LocalPinnedConnection(_PinnedHTTPSConnection):
    """Test-only loopback dial while retaining production TLS hostname checks."""
    def connect(self):
        raw = __import__("socket").create_connection(
            ("127.0.0.1", self.port), timeout=self.timeout
        )
        try:
            tls_socket = self._context.wrap_socket(raw, server_hostname=self.host)
            actual = hashlib.sha256(
                tls_socket.getpeercert(binary_form=True)
            ).hexdigest()
            if actual != self._expected_fingerprint:
                tls_socket.close()
                raise OSError("test certificate pin mismatch")
            self.sock = tls_socket
        except Exception:
            raw.close()
            raise


@pytest.fixture
def integrated_transport(tmp_path):
    backend_private, backend_public = _ed_pair()
    worker_private, worker_public = _ed_pair()
    (ca, server_cert, server_key, client_cert, client_key,
     server_pin, client_pin) = _certificates(tmp_path)

    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_cert_chain(server_cert, server_key)
    server_context.load_verify_locations(cafile=ca)

    server = _ThreadingHTTPServer(
        ("127.0.0.1", 0),
        build_handler(
            backend_public_key=backend_public,
            worker_private_key=worker_private,
            worker_id="worker-e2e",
            key_id="worker-key-1",
        ),
    )
    server.expected_client_certificate_sha256 = client_pin
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    engine = create_engine("sqlite://")
    for model in (ScanJob, WorkerTaskReceipt, WorkerKey, WorkerEndpoint, WorkerDispatchAttempt):
        model.__table__.create(engine)

    try:
        with Session(engine) as db:
            now = datetime.now(timezone.utc)
            job = ScanJob(
                id=501, project_id=1, target_id=1, scope_snapshot_id=9,
                created_by=1, profile="passive_recon", status="dispatch_reserved",
                execution_enabled=False,
            )
            db.add(job)
            db.add(WorkerKey(
                worker_id="worker-e2e", key_id="worker-key-1",
                public_key_b64=worker_public,
                fingerprint_sha256=hashlib.sha256(worker_public.encode()).hexdigest(),
                status="active",
            ))
            endpoint = WorkerEndpoint(
                worker_id="worker-e2e",
                base_url=f"https://worker.example.org:{server.server_address[1]}",
                tls_server_name="worker.example.org",
                certificate_sha256=server_pin,
                status="active",
            )
            db.add(endpoint)
            db.commit()

            envelope = WorkerTaskEnvelope(
                task_id=uuid4(), job_id=501, scope_snapshot_id=9,
                scope_snapshot_sha256="c" * 64, profile="passive_recon",
                target_url="https://authorized.example/",
                issued_at=now, expires_at=now + timedelta(minutes=3),
                execution_enabled=False,
            )
            signed = sign_worker_task(
                envelope, backend_private,
                worker_id="worker-e2e", key_id="worker-key-1",
            )
            db.add(WorkerTaskReceipt(
                task_id=str(envelope.task_id), job_id=501,
                envelope_sha256=worker_task_digest(envelope),
                worker_id="worker-e2e", key_id="worker-key-1",
                expires_at=envelope.expires_at, consumed_at=None, created_at=now,
            ))
            db.commit()

            def resolver(host, port):
                assert host == "worker.example.org"
                return ["93.184.216.34"]

            result = deliver_signed_worker_task(
                db, signed, resolver=resolver,
                client_certificate_path=client_cert,
                client_private_key_path=client_key,
                ca_certificate_path=ca,
                connection_factory=_LocalPinnedConnection,
            )
            receipt = db.query(WorkerTaskReceipt).filter_by(
                task_id=str(envelope.task_id)
            ).one()
            attempt = db.query(WorkerDispatchAttempt).filter_by(
                task_id=str(envelope.task_id)
            ).one()
            yield {
                "result": result,
                "receipt": receipt,
                "attempt": attempt,
                "db": db,
            }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        engine.dispose()


def test_backend_to_worker_full_mtls_dispatch_and_ack(integrated_transport):
    state = integrated_transport
    assert state["result"]["http_status"] == 200
    assert state["result"]["acknowledgement"]["result"]["outcome"] == "accepted"
    assert state["result"]["acknowledgement"]["result"]["execution_enabled"] is False
    assert state["receipt"].consumed_at is not None
    assert state["attempt"].status == "delivered"


def test_full_dispatch_does_not_enable_scan_execution(integrated_transport):
    state = integrated_transport
    assert state["result"]["acknowledgement"]["execution_enabled"] is False
    assert state["attempt"].status == "delivered"
