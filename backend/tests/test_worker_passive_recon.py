import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.core.worker_observation_signing import verify_worker_observation_batch
from app.core.worker_protocol import WorkerTaskEnvelope
from worker_passive_recon import (
    MAX_FEED_BYTES,
    PassiveFeedRecord,
    build_signed_passive_batch,
    read_passive_feed,
)


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


def make_task(now=None, rules=None):
    current = now or datetime.now(timezone.utc)
    return WorkerTaskEnvelope(
        task_id=uuid4(), job_id=7, scope_snapshot_id=3,
        scope_snapshot_sha256="a" * 64, profile="passive_recon",
        target_url="https://example.org/",
        approved_scope_rules=rules or ["example.org", "*.example.org"],
        issued_at=current - timedelta(seconds=1),
        expires_at=current + timedelta(minutes=2),
        execution_enabled=False,
    )


def record(host="api.example.org", kind="hostname", value="api.example.org", source="ct_log"):
    return PassiveFeedRecord(
        hostname=host, kind=kind, value=value, evidence="certificate transparency",
        source=source, observed_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )


def test_passive_producer_filters_out_of_scope_and_signs_results():
    now = datetime.now(timezone.utc)
    private, public = keypair()
    task = make_task(now)
    records = [
        record(),
        record("attacker.invalid", value="attacker.invalid"),
        record("www.example.org", kind="url", value="https://www.example.org/login", source="passive_url"),
    ]
    signed = build_signed_passive_batch(
        task, records, worker_id="worker-1", key_id="key-1",
        worker_private_key_b64=private, now=now,
    )
    assert signed is not None
    assert len(signed.batch.observations) == 2
    assert all("attacker.invalid" not in item.value for item in signed.batch.observations)
    assert signed.batch.execution_enabled is False
    assert signed.batch.envelope_sha256
    assert verify_worker_observation_batch(signed, public)


def test_passive_producer_returns_none_when_no_in_scope_records():
    now = datetime.now(timezone.utc)
    private, _ = keypair()
    result = build_signed_passive_batch(
        make_task(now), [record("outside.invalid", value="outside.invalid")],
        worker_id="worker-1", key_id="key-1",
        worker_private_key_b64=private, now=now,
    )
    assert result is None


def test_passive_producer_rejects_missing_scope_and_future_observation():
    now = datetime.now(timezone.utc)
    private, _ = keypair()
    task = make_task(now, rules=["example.org"])
    task = task.model_copy(update={"approved_scope_rules": []})
    with pytest.raises(ValueError, match="scope manifest"):
        build_signed_passive_batch(
            task, [record()], worker_id="worker-1", key_id="key-1",
            worker_private_key_b64=private, now=now,
        )
    future_record = record().model_copy(update={"observed_at": now + timedelta(seconds=5)})
    with pytest.raises(ValueError, match="future"):
        build_signed_passive_batch(
            make_task(now), [future_record], worker_id="worker-1", key_id="key-1",
            worker_private_key_b64=private, now=now,
        )


def test_feed_record_rejects_url_host_mismatch_and_sensitive_query():
    with pytest.raises(ValidationError, match="does not match"):
        record("example.org", kind="url", value="https://outside.invalid/a")
    with pytest.raises(ValidationError, match="query"):
        record("example.org", kind="url", value="https://example.org/path?token=secret")


def test_feed_reader_requires_bounded_regular_private_file(tmp_path):
    path = tmp_path / "feed.json"
    path.write_text(json.dumps([{
        "hostname": "api.example.org",
        "kind": "hostname",
        "value": "api.example.org",
        "evidence": "ct",
        "source": "ct_log",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }]))
    path.chmod(0o600)
    assert len(read_passive_feed(path)) == 1

    insecure = tmp_path / "insecure.json"
    insecure.write_text("[]")
    insecure.chmod(0o666)
    with pytest.raises(ValueError, match="writable"):
        read_passive_feed(insecure)

    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="non-symlink"):
        read_passive_feed(link)


def test_feed_reader_rejects_oversized_input(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b"[" + b" " * MAX_FEED_BYTES + b"]")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="size"):
        read_passive_feed(path)


def test_passive_producer_preserves_host_binding_for_dns_and_technology():
    now = datetime.now(timezone.utc)
    private, _ = keypair()
    records = [
        PassiveFeedRecord(
            hostname="api.example.org", kind="technology", value="nginx",
            evidence="server banner", source="offline_inventory",
            observed_at=now - timedelta(seconds=1),
        ),
        PassiveFeedRecord(
            hostname="api.example.org", kind="dns_record", value="A 203.0.113.10",
            evidence="passive DNS feed", source="passive_dns",
            observed_at=now - timedelta(seconds=1),
        ),
    ]
    signed = build_signed_passive_batch(
        make_task(now), records, worker_id="worker-1", key_id="key-1",
        worker_private_key_b64=private, now=now,
    )
    assert signed is not None
    assert {item.kind for item in signed.batch.observations} == {"technology", "dns_record"}
    assert all(item.evidence.startswith("hostname=api.example.org;") for item in signed.batch.observations)
