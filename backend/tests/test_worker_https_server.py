import base64
import json
from datetime import datetime, timedelta, timezone
from email.message import Message
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.worker_protocol import WorkerTaskEnvelope
from app.core.worker_signing import (
    SignedWorkerValidationResult,
    sign_worker_task,
    verify_worker_validation_result,
)
from worker_https_server import (
    MAX_BODY_BYTES,
    validate_http_task_headers,
    validate_task_request,
)
from worker_replay_ledger import ReplayConflict, WorkerReplayLedger


def keypair():
    key = Ed25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )).decode()
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    return private, public


def make_task():
    now = datetime.now(timezone.utc)
    return WorkerTaskEnvelope(
        task_id=uuid4(), job_id=10, scope_snapshot_id=20,
        scope_snapshot_sha256="a" * 64, profile="passive_recon",
        target_url="https://example.com/", issued_at=now,
        expires_at=now + timedelta(minutes=2), execution_enabled=False,
    )


def test_https_worker_returns_signed_validation_ack():
    backend_private, backend_public = keypair()
    worker_private, worker_public = keypair()
    task = sign_worker_task(
        make_task(), backend_private, worker_id="worker-1", key_id="key-1"
    )
    response = validate_task_request(
        task.model_dump_json().encode(),
        backend_public_key=backend_public,
        worker_private_key=worker_private,
        worker_id="worker-1",
        key_id="key-1",
    )
    ack = SignedWorkerValidationResult.model_validate_json(response)
    assert ack.result.outcome == "accepted"
    assert ack.result.execution_enabled is False
    assert verify_worker_validation_result(
        ack, worker_public, expected_worker_id="worker-1", expected_key_id="key-1"
    )


def test_https_worker_rejects_tampered_task():
    backend_private, backend_public = keypair()
    worker_private, _ = keypair()
    task = sign_worker_task(
        make_task(), backend_private, worker_id="worker-1", key_id="key-1"
    )
    payload = json.loads(task.model_dump_json())
    payload["envelope"]["job_id"] = 999
    with pytest.raises(ValueError, match="signature"):
        validate_task_request(
            json.dumps(payload).encode(),
            backend_public_key=backend_public,
            worker_private_key=worker_private,
            worker_id="worker-1",
            key_id="key-1",
        )


def test_https_worker_rejects_wrong_worker_identity():
    backend_private, backend_public = keypair()
    worker_private, _ = keypair()
    task = sign_worker_task(
        make_task(), backend_private, worker_id="other", key_id="key-1"
    )
    with pytest.raises(ValueError, match="signature"):
        validate_task_request(
            task.model_dump_json().encode(),
            backend_public_key=backend_public,
            worker_private_key=worker_private,
            worker_id="worker-1",
            key_id="key-1",
        )


def test_https_worker_rejects_oversized_body():
    _, backend_public = keypair()
    worker_private, _ = keypair()
    with pytest.raises(ValueError, match="body size"):
        validate_task_request(
            b"x" * (MAX_BODY_BYTES + 1),
            backend_public_key=backend_public,
            worker_private_key=worker_private,
            worker_id="worker-1",
            key_id="key-1",
        )



def _headers(**values):
    message = Message()
    for name, value in values.items():
        items = value if isinstance(value, list) else [value]
        for item in items:
            message.add_header(name.replace("_", "-"), item)
    return message


@pytest.mark.parametrize(
    "headers,expected",
    [
        (_headers(Host="worker.example", Content_Type="application/json",
                  Content_Length="2"), (200, 2)),
        (_headers(Content_Type="application/json", Content_Length="2"), (400, None)),
        (_headers(Host=["worker.example", "attacker.example"],
                  Content_Type="application/json", Content_Length="2"), (400, None)),
        (_headers(Host="worker.example", Content_Type="application/json",
                  Content_Length=["2", "3"]), (400, None)),
        (_headers(Host="worker.example", Content_Type="application/json",
                  Content_Length="2", Transfer_Encoding="chunked"), (400, None)),
        (_headers(Host="worker.example", Content_Type="application/json",
                  Content_Length="2", Content_Encoding="gzip"), (400, None)),
        (_headers(Host="worker.example", Content_Type="application/json",
                  Content_Length="2", Expect="100-continue"), (417, None)),
        (_headers(Host="worker.example", Content_Type="application/json",
                  Content_Length="+2"), (400, None)),
        (_headers(Host="worker.example", Content_Type="application/json",
                  Content_Length="0"), (413, None)),
    ],
)
def test_http_task_header_framing_is_strict(headers, expected):
    assert validate_http_task_headers(headers) == expected


def test_https_worker_replay_returns_identical_persisted_ack(tmp_path):
    backend_private, backend_public = keypair()
    worker_private, _ = keypair()
    ledger_path = tmp_path / "worker.sqlite3"
    ledger = WorkerReplayLedger(ledger_path)
    task = sign_worker_task(
        make_task(), backend_private, worker_id="worker-1", key_id="key-1"
    )
    raw = task.model_dump_json().encode()
    first = validate_task_request(
        raw, backend_public_key=backend_public, worker_private_key=worker_private,
        worker_id="worker-1", key_id="key-1", replay_ledger=ledger,
    )
    reopened = WorkerReplayLedger(ledger_path)
    replay = validate_task_request(
        raw, backend_public_key=backend_public, worker_private_key=worker_private,
        worker_id="worker-1", key_id="key-1", replay_ledger=reopened,
    )
    assert replay == first

    altered_envelope = task.envelope.model_copy(update={"job_id": 999})
    altered = sign_worker_task(
        altered_envelope, backend_private, worker_id="worker-1", key_id="key-1"
    )
    with pytest.raises(ReplayConflict):
        validate_task_request(
            altered.model_dump_json().encode(),
            backend_public_key=backend_public, worker_private_key=worker_private,
            worker_id="worker-1", key_id="key-1", replay_ledger=reopened,
        )


def test_expired_task_is_not_written_to_replay_ledger(tmp_path):
    backend_private, backend_public = keypair()
    worker_private, _ = keypair()
    ledger_path = tmp_path / "worker.sqlite3"
    ledger = WorkerReplayLedger(ledger_path)
    task = make_task().model_copy(update={
        "expires_at": datetime.now(timezone.utc) - timedelta(seconds=5),
    })
    signed = sign_worker_task(
        task, backend_private, worker_id="worker-1", key_id="key-1"
    )
    with pytest.raises(ValueError):
        validate_task_request(
            signed.model_dump_json().encode(),
            backend_public_key=backend_public, worker_private_key=worker_private,
            worker_id="worker-1", key_id="key-1", replay_ledger=ledger,
        )
    import sqlite3
    with sqlite3.connect(ledger_path) as db:
        count = db.execute("SELECT COUNT(*) FROM worker_task_ledger").fetchone()[0]
    assert count == 0
