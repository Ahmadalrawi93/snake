from sqlalchemy import create_engine
from sqlalchemy.orm import Session
import pytest

from app.core.worker_endpoint_registry import (
    register_worker_endpoint, revoke_worker_endpoint, validate_worker_endpoint,
)
from app.db.models import WorkerEndpoint


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    WorkerEndpoint.__table__.create(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def test_register_canonical_https_endpoint_with_certificate_pin(db):
    row = register_worker_endpoint(
        db, worker_id="worker-a", base_url="https://worker.example.org:443/",
        tls_server_name="worker.example.org", certificate_sha256="A" * 64,
        created_by=1,
    )
    db.commit()
    assert row.base_url == "https://worker.example.org"
    assert row.certificate_sha256 == "a" * 64
    assert row.status == "active"


@pytest.mark.parametrize("url", [
    "http://worker.example.org",
    "https://user:pass@worker.example.org",
    "https://127.0.0.1",
    "https://worker.example.org:0",
    "https://localhost",
    "https://worker.example.org/private",
    "https://worker.example.org?next=example",
    "https://worker.example.org#fragment",
])
def test_reject_unsafe_endpoint_url_shapes(url):
    with pytest.raises(ValueError):
        validate_worker_endpoint(url, "worker.example.org", "a" * 64)


def test_tls_server_name_must_match_endpoint_host():
    with pytest.raises(ValueError, match="must match"):
        validate_worker_endpoint(
            "https://worker.example.org", "attacker.example.net", "a" * 64
        )


def test_certificate_pin_must_be_sha256_hex():
    with pytest.raises(ValueError, match="64 hexadecimal"):
        validate_worker_endpoint(
            "https://worker.example.org", "worker.example.org", "not-a-pin"
        )


def test_endpoint_is_one_per_worker_and_revocation_is_one_way(db):
    register_worker_endpoint(
        db, worker_id="worker-a", base_url="https://worker.example.org",
        tls_server_name="worker.example.org", certificate_sha256="a" * 64,
        created_by=1,
    )
    db.commit()
    with pytest.raises(ValueError, match="already exists"):
        register_worker_endpoint(
            db, worker_id="worker-a", base_url="https://worker2.example.org",
            tls_server_name="worker2.example.org", certificate_sha256="b" * 64,
            created_by=1,
        )
    row = revoke_worker_endpoint(db, worker_id="worker-a")
    assert row.status == "revoked"
    db.commit()
    with pytest.raises(ValueError, match="already revoked"):
        revoke_worker_endpoint(db, worker_id="worker-a")
