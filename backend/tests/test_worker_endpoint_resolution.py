from sqlalchemy import create_engine
from sqlalchemy.orm import Session
import pytest

from app.core.worker_endpoint_registry import register_worker_endpoint, revoke_worker_endpoint
from app.core.worker_endpoint_resolution import resolve_registered_worker_endpoint
from app.core.network_policy import NetworkPolicyError
from app.db.models import WorkerEndpoint


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    WorkerEndpoint.__table__.create(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def add_endpoint(db):
    register_worker_endpoint(
        db, worker_id="worker-a", base_url="https://worker.example.org",
        tls_server_name="worker.example.org", certificate_sha256="a" * 64,
        created_by=None,
    )
    db.commit()


def resolver_for(records):
    def resolve(host, port):
        return records.get(host, [])
    return resolve


def test_active_endpoint_resolves_to_pinned_public_ip(db):
    add_endpoint(db)
    endpoint, destination = resolve_registered_worker_endpoint(
        db, worker_id="worker-a",
        resolver=resolver_for({"worker.example.org": ["93.184.216.34"]}),
    )
    assert endpoint.certificate_sha256 == "a" * 64
    assert destination.hostname == "worker.example.org"
    assert destination.port == 443
    assert destination.addresses == ("93.184.216.34",)


def test_private_dns_answer_blocks_worker_destination(db):
    add_endpoint(db)
    with pytest.raises(NetworkPolicyError, match="non_public_ip_address"):
        resolve_registered_worker_endpoint(
            db, worker_id="worker-a",
            resolver=resolver_for({"worker.example.org": ["93.184.216.34", "10.0.0.5"]}),
        )


def test_revoked_endpoint_cannot_be_resolved(db):
    add_endpoint(db)
    revoke_worker_endpoint(db, worker_id="worker-a")
    db.commit()
    with pytest.raises(ValueError, match="not registered and active"):
        resolve_registered_worker_endpoint(
            db, worker_id="worker-a",
            resolver=resolver_for({"worker.example.org": ["93.184.216.34"]}),
        )


def test_missing_dns_answer_blocks_worker_destination(db):
    add_endpoint(db)
    with pytest.raises(NetworkPolicyError, match="dns_no_addresses"):
        resolve_registered_worker_endpoint(
            db, worker_id="worker-a", resolver=resolver_for({}),
        )
