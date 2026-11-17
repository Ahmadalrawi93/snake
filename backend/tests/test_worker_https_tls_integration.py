import base64
import hashlib
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import http.client
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.core.worker_protocol import WorkerTaskEnvelope
from app.core.worker_signing import (
    sign_worker_task,
    verify_worker_validation_result,
)
from app.schemas.worker_transport import WorkerTaskResponse
from worker_https_server import TASK_PATH, _ThreadingHTTPServer, build_handler


def _write_pem(path: Path, value: bytes):
    path.write_bytes(value)


def _issue_cert(*, subject_name, issuer_name, issuer_key, public_key,
                is_ca, san_dns=None, extended_usage=None):
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
    )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san_dns)]), critical=False
        )
    if extended_usage:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([extended_usage]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _tls_material(directory: Path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SNAKE Test CA")])
    ca_cert = _issue_cert(
        subject_name="SNAKE Test CA", issuer_name=ca_name,
        issuer_key=ca_key, public_key=ca_key.public_key(), is_ca=True,
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = _issue_cert(
        subject_name="localhost", issuer_name=ca_name, issuer_key=ca_key,
        public_key=server_key.public_key(), is_ca=False, san_dns="localhost",
        extended_usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = _issue_cert(
        subject_name="snake-backend", issuer_name=ca_name, issuer_key=ca_key,
        public_key=client_key.public_key(), is_ca=False,
        extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    ca_path = directory / "ca.pem"
    server_cert_path = directory / "server.pem"
    server_key_path = directory / "server-key.pem"
    client_cert_path = directory / "client.pem"
    client_key_path = directory / "client-key.pem"
    _write_pem(ca_path, ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(server_cert_path, server_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(server_key_path, server_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    _write_pem(client_cert_path, client_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(client_key_path, client_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return ca_path, server_cert_path, server_key_path, client_cert_path, client_key_path, ca_cert


def _ed25519_pair():
    key = ed25519.Ed25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )).decode()
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    return private, public


def _task(backend_private):
    now = datetime.now(timezone.utc)
    envelope = WorkerTaskEnvelope(
        task_id=uuid4(), job_id=22, scope_snapshot_id=33,
        scope_snapshot_sha256="b" * 64, profile="passive_recon",
        target_url="https://example.com/", issued_at=now,
        expires_at=now + timedelta(minutes=2), execution_enabled=False,
    )
    return sign_worker_task(
        envelope, backend_private, worker_id="worker-tls", key_id="tls-key"
    )


@pytest.fixture
def live_mtls_worker(tmp_path):
    backend_private, backend_public = _ed25519_pair()
    worker_private, worker_public = _ed25519_pair()
    ca_path, server_cert, server_key, client_cert, client_key, ca_cert = _tls_material(tmp_path)

    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_cert_chain(str(server_cert), str(server_key))
    server_context.load_verify_locations(cafile=str(ca_path))

    server = _ThreadingHTTPServer(
        ("127.0.0.1", 0),
        build_handler(
            backend_public_key=backend_public,
            worker_private_key=worker_private,
            worker_id="worker-tls",
            key_id="tls-key",
        ),
    )
    server.expected_client_certificate_sha256 = hashlib.sha256(
        x509.load_pem_x509_certificate(client_cert.read_bytes()).public_bytes(
            serialization.Encoding.DER
        )
    ).hexdigest()
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "host": "localhost",
            "port": server.server_address[1],
            "ca": ca_path,
            "client_cert": client_cert,
            "client_key": client_key,
            "backend_private": backend_private,
            "worker_public": worker_public,
            "ca_cert": ca_cert,
            "server": server,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_https_mtls_task_and_signed_ack(live_mtls_worker):
    cfg = live_mtls_worker
    task = _task(cfg["backend_private"])
    context = ssl.create_default_context(cafile=str(cfg["ca"]))
    context.load_cert_chain(str(cfg["client_cert"]), str(cfg["client_key"]))
    connection = http.client.HTTPSConnection(
        cfg["host"], cfg["port"], context=context, timeout=3
    )
    try:
        connection.request(
            "POST", TASK_PATH, body=task.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        payload = response.read(64 * 1024 + 1)
        assert response.status == 200
        worker_response = WorkerTaskResponse.model_validate_json(payload)
        ack = worker_response.acknowledgement
        assert worker_response.observation_batch is None
        assert ack.result.execution_enabled is False
        assert verify_worker_validation_result(
            ack, cfg["worker_public"],
            expected_worker_id="worker-tls", expected_key_id="tls-key",
        )
    finally:
        connection.close()


def test_real_https_rejects_client_without_certificate(live_mtls_worker):
    cfg = live_mtls_worker
    context = ssl.create_default_context(cafile=str(cfg["ca"]))
    connection = http.client.HTTPSConnection(
        cfg["host"], cfg["port"], context=context, timeout=3
    )
    try:
        with pytest.raises((ssl.SSLError, OSError, http.client.RemoteDisconnected)):
            connection.request("POST", TASK_PATH, body=b"{}", headers={
                "Content-Type": "application/json",
            })
            connection.getresponse()
    finally:
        connection.close()


def test_real_https_rejects_unpinned_backend_client_certificate(live_mtls_worker):
    cfg = live_mtls_worker
    cfg["server"].expected_client_certificate_sha256 = "0" * 64
    context = ssl.create_default_context(cafile=str(cfg["ca"]))
    context.load_cert_chain(str(cfg["client_cert"]), str(cfg["client_key"]))
    connection = http.client.HTTPSConnection(
        cfg["host"], cfg["port"], context=context, timeout=3
    )
    try:
        with pytest.raises((ssl.SSLError, OSError, http.client.RemoteDisconnected)):
            connection.request("POST", TASK_PATH, body=b"{}", headers={
                "Content-Type": "application/json",
            })
            connection.getresponse()
    finally:
        connection.close()
