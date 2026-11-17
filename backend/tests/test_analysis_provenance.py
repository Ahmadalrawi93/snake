import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4, UUID
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db.database import Base
from app.db.models import (
    User, Project, Target, Authorization, ScopeSnapshot, ScanJob,
    WorkerTaskReceipt, WorkerKey, WorkerObservationRecord, AIAnalysisRun, Project, Target,
)
from app.core.worker_signing import ed25519_public_key_fingerprint
from app.core.worker_observation_signing import sign_worker_observation_batch, observation_batch_digest
from app.core.analysis_provenance import build_persisted_analysis_input, bind_analysis_run_provenance, load_verified_analysis_run_context
from app.schemas.worker_results import WorkerObservation, WorkerObservationBatch


def _keypair():
    key = Ed25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )).decode()
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    return private, public


@pytest.fixture
def provenance_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    now = datetime.now(timezone.utc)
    private, public = _keypair()
    user = User(email="provenance@example.test", password_hash="test")
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name="Provenance")
    db.add(project)
    db.flush()
    target = Target(project_id=project.id, value="https://example.test", target_type="url", status="registered")
    db.add(target)
    db.flush()
    auth = Authorization(
        project_id=project.id, reference="authorized test program",
        starts_at=(now - timedelta(minutes=2)).isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
        status="approved", scope_rules='["example.test", "*.example.test"]',
    )
    db.add(auth)
    db.flush()
    snapshot_data = {
        "schema_version": 1, "project_id": project.id, "target_id": target.id,
        "target": "https://example.test", "hostname": "example.test",
        "authorization_id": auth.id, "authorization_reference": auth.reference,
        "authorization_status": "approved", "approved_scope_rules": ["example.test", "*.example.test"],
        "created_at": now.isoformat(), "authorization_expires_at": auth.expires_at,
        "policy": "hostname-allowlist-v1", "execution_enabled": False,
    }
    snapshot_json = json.dumps(snapshot_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    snapshot = ScopeSnapshot(
        project_id=project.id, target_id=target.id, authorization_id=auth.id,
        created_by=user.id, snapshot_json=snapshot_json,
        sha256=hashlib.sha256(snapshot_json.encode()).hexdigest(),
        status="active", expires_at=auth.expires_at,
    )
    db.add(snapshot)
    db.flush()
    job = ScanJob(
        project_id=project.id, target_id=target.id, scope_snapshot_id=snapshot.id,
        created_by=user.id, profile="passive_recon", status="dispatch_reserved",
        execution_enabled=False,
    )
    db.add(job)
    db.flush()
    task_id = uuid4()
    receipt = WorkerTaskReceipt(
        task_id=str(task_id), job_id=job.id, envelope_sha256="a" * 64,
        worker_id="worker-01", key_id="key-01", expires_at=now + timedelta(minutes=3),
        consumed_at=now, acknowledgement_outcome="accepted",
        acknowledgement_worker_id="worker-01", created_at=now - timedelta(seconds=30),
    )
    db.add(receipt)
    db.add(WorkerKey(
        worker_id="worker-01", key_id="key-01", public_key_b64=public,
        fingerprint_sha256=ed25519_public_key_fingerprint(public), status="active",
    ))
    db.flush()
    batch = WorkerObservationBatch(
        task_id=task_id, envelope_sha256="a" * 64, worker_id="worker-01", key_id="key-01",
        collected_at=now - timedelta(seconds=5),
        observations=[WorkerObservation(
            observation_id=uuid4(), kind="hostname", value="api.example.test",
            evidence="passive DNS answer", source="passive_dns",
            observed_at=now - timedelta(seconds=8),
        )],
        execution_enabled=False,
    )
    signed = sign_worker_observation_batch(batch, private)
    payload = json.dumps(batch.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    item = batch.observations[0]
    db.add(WorkerObservationRecord(
        observation_id=str(item.observation_id), task_id=str(task_id),
        worker_id="worker-01", key_id="key-01", envelope_sha256="a" * 64,
        batch_sha256=observation_batch_digest(batch), batch_signature=signed.signature,
        batch_payload_json=payload, kind=item.kind, value=item.value, evidence=item.evidence,
        source=item.source, observed_at=item.observed_at, collected_at=batch.collected_at,
        received_at=now, classification="unconfirmed_observation",
    ))
    db.commit()
    yield db, user, project, target, private, now
    db.close()
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_build_context_from_signed_persisted_worker_observations(provenance_db):
    db, user, project, target, _, now = provenance_db
    source = build_persisted_analysis_input(db, project_id=project.id, target_id=target.id, actor=user, now=now)
    assert source.context.total_observations == 1
    assert source.context.ungrouped == []
    assert source.context.groups[0].host_key == "api.example.test"
    assert len(source.provenance_sha256) == 64


def test_provenance_links_rebuild_exact_context_and_signature(provenance_db):
    db, user, project, target, _, now = provenance_db
    source = build_persisted_analysis_input(db, project_id=project.id, target_id=target.id, actor=user, now=now)
    from app.core.analysis_orchestrator import _digest
    run = AIAnalysisRun(
        project_id=project.id, target_id=target.id, created_by=user.id,
        context_sha256=_digest(source.context.model_dump(mode="json")),
        correlations_sha256=_digest(source.correlations.model_dump(mode="json")),
        provider="deepseek", model="test", status="completed",
        disposition="requires_independent_validation", result_json="{}",
        execution_enabled=False,
    )
    db.add(run)
    db.flush()
    bind_analysis_run_provenance(db, run=run, project_id=project.id, target_id=target.id, source=source)
    db.query(ScopeSnapshot).filter_by(id=1).one().status = "revoked"
    db.query(Authorization).filter_by(id=1).one().status = "revoked"
    db.query(WorkerKey).filter_by(worker_id="worker-01", key_id="key-01").one().status = "revoked"
    db.commit()
    rebuilt, _ = load_verified_analysis_run_context(db, run=run)
    assert _digest(rebuilt.model_dump(mode="json")) == run.context_sha256
    assert run.source_observation_count == 1


def test_rejects_unowned_target(provenance_db):
    db, user, project, target, _, now = provenance_db
    other = User(email="not-owner@example.test", password_hash="test")
    db.add(other)
    db.commit()
    with pytest.raises(LookupError, match="target not found"):
        build_persisted_analysis_input(db, project_id=project.id, target_id=target.id, actor=other, now=now)


def test_rejects_tampered_signed_batch_payload(provenance_db):
    db, user, project, target, _, now = provenance_db
    row = db.query(WorkerObservationRecord).one()
    payload = json.loads(row.batch_payload_json)
    payload["observations"][0]["value"] = "attacker.example.test"
    row.batch_payload_json = json.dumps(payload)
    db.commit()
    with pytest.raises(ValueError, match="signature or digest"):
        build_persisted_analysis_input(db, project_id=project.id, target_id=target.id, actor=user, now=now)



def test_rejects_observation_row_not_matching_signed_batch(provenance_db):
    db, user, project, target, _, now = provenance_db
    row = db.query(WorkerObservationRecord).one()
    row.value = "forged.example.test"
    db.commit()
    with pytest.raises(ValueError, match="does not match its signed batch"):
        build_persisted_analysis_input(db, project_id=project.id, target_id=target.id, actor=user, now=now)


def test_revoked_worker_key_cannot_source_a_new_analysis(provenance_db):
    db, user, project, target, _, now = provenance_db
    db.query(WorkerKey).filter_by(worker_id="worker-01", key_id="key-01").one().status = "revoked"
    db.commit()
    with pytest.raises(ValueError, match="revoked for new analysis"):
        build_persisted_analysis_input(db, project_id=project.id, target_id=target.id, actor=user, now=now)


def test_rejects_signed_observation_outside_approved_scope(provenance_db):
    db, user, project, target, private, now = provenance_db
    row = db.query(WorkerObservationRecord).one()
    batch = WorkerObservationBatch(
        task_id=UUID(row.task_id), envelope_sha256=row.envelope_sha256,
        worker_id=row.worker_id, key_id=row.key_id,
        collected_at=now - timedelta(seconds=5),
        observations=[WorkerObservation(
            observation_id=UUID(row.observation_id), kind="hostname",
            value="outside.invalid", evidence="signed but outside scope",
            source="passive_dns", observed_at=now - timedelta(seconds=8),
        )],
        execution_enabled=False,
    )
    signed = sign_worker_observation_batch(batch, private)
    row.value = "outside.invalid"
    row.evidence = "signed but outside scope"
    row.batch_sha256 = observation_batch_digest(batch)
    row.batch_signature = signed.signature
    row.batch_payload_json = json.dumps(
        batch.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    db.commit()
    with pytest.raises(ValueError, match="outside approved target scope"):
        build_persisted_analysis_input(
            db, project_id=project.id, target_id=target.id, actor=user, now=now
        )


def test_rejects_ip_only_observation_without_hostname_scope_binding(provenance_db):
    db, user, project, target, private, now = provenance_db
    row = db.query(WorkerObservationRecord).one()
    batch = WorkerObservationBatch(
        task_id=UUID(row.task_id), envelope_sha256=row.envelope_sha256,
        worker_id=row.worker_id, key_id=row.key_id,
        collected_at=now - timedelta(seconds=5),
        observations=[WorkerObservation(
            observation_id=UUID(row.observation_id), kind="ip",
            value="203.0.113.7", evidence="unbound IP",
            source="passive_dns", observed_at=now - timedelta(seconds=8),
        )],
        execution_enabled=False,
    )
    signed = sign_worker_observation_batch(batch, private)
    row.kind = "ip"
    row.value = "203.0.113.7"
    row.evidence = "unbound IP"
    row.batch_sha256 = observation_batch_digest(batch)
    row.batch_signature = signed.signature
    row.batch_payload_json = json.dumps(
        batch.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    db.commit()
    with pytest.raises(ValueError, match="outside approved target scope"):
        build_persisted_analysis_input(
            db, project_id=project.id, target_id=target.id, actor=user, now=now
        )


def test_investigation_memory_is_persistent_and_target_scoped(provenance_db):
    from app.core.investigation_memory import record_and_compare_investigation_memory
    from app.schemas.validation_strategy import ValidationStrategyItem
    db, user, project, target, _, now = provenance_db
    strategy = ValidationStrategyItem(
        strategy_id="object_review", category="object_authorization", priority="high",
        priority_basis="Review ownership boundary", hypothesis="A user may access another user's invoice",
        supporting_observation_ids=["obs-a", "obs-b"], missing_evidence=[],
        validation_questions=["Check expected ownership"], manual_review_actions=["Review authorized test evidence"],
        prerequisites=["Written authorization"],
    )
    def make_run(target_id):
        run = AIAnalysisRun(project_id=project.id, target_id=target_id, created_by=user.id,
            context_sha256="a"*64, correlations_sha256="b"*64, provider="deepseek", model="test",
            status="completed", disposition="requires_independent_validation", result_json="{}", execution_enabled=False)
        db.add(run); db.flush()
        return run
    first = make_run(target.id)
    initial = record_and_compare_investigation_memory(db, run=first, strategy=strategy, actor=user)
    assert initial.prior_matches == []
    second = make_run(target.id)
    repeated = record_and_compare_investigation_memory(db, run=second, strategy=strategy, actor=user)
    assert len(repeated.prior_matches) == 1
    assert repeated.prior_matches[0].shared_observation_count == 2
    assert repeated.prior_matches[0].new_observation_count == 0
    assert repeated.prior_matches[0].disposition == "previously_seen_no_new_observations"
    other_target = Target(project_id=project.id, value="https://other.example.test", target_type="url", status="registered")
    db.add(other_target); db.flush()
    third = make_run(other_target.id)
    isolated = record_and_compare_investigation_memory(db, run=third, strategy=strategy, actor=user)
    assert isolated.prior_matches == []
    assert isolated.review_suppressed is False
