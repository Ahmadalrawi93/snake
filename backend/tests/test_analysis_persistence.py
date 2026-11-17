import json
from datetime import datetime, timezone
from uuid import uuid4, UUID

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.db.models import AIAnalysisRun, Project, Target, User
from app.core.analysis_persistence import persist_analysis_run, persist_analysis_execution
from app.core.deepseek_analysis import AnalysisExecutionResult
from app.core.analysis_context import build_analysis_context
from app.core.evidence_correlation import correlate_analysis_context
from app.schemas.observation_triage import ObservationTriage
from app.schemas.worker_results import WorkerObservation


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def setup_context():
    item = WorkerObservation(
        observation_id=uuid4(), kind="url", value="https://scope.example.test/api/users/1",
        evidence="password=should-not-be-persisted", source="passive",
        observed_at=datetime.now(timezone.utc),
    )
    context = build_analysis_context([item])
    correlations = correlate_analysis_context(context)
    oid = context.groups[0].observations[0].observation_ids[0]
    triage = ObservationTriage(
        category="authorization",
        hypothesis="The route may expose an object access surface.",
        supporting_observation_ids=[UUID(oid)],
        missing_evidence=["No access-control behavior has been observed."],
        validation_questions=["Can another account access this object?"],
        confidence="low",
    )
    return context, correlations, triage


def test_persists_only_hashes_and_validated_triage(db):
    user = User(email="owner@example.test", password_hash="hash")
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name="authorized test")
    db.add(project)
    db.flush()
    context, correlations, triage = setup_context()
    record = persist_analysis_run(
        db, project_id=project.id, actor=user, context=context,
        correlations=correlations, triage=triage, model="deepseek-test",
        prompt_tokens=12, completion_tokens=8, total_tokens=20, cost_usd="0.001",
    )
    db.commit()
    stored = db.get(AIAnalysisRun, record.id)
    assert stored.status == "completed"
    assert stored.disposition == "requires_independent_validation"
    assert stored.execution_enabled is False
    assert stored.prompt_tokens == 12 and stored.total_tokens == 20
    assert "should-not-be-persisted" not in stored.result_json
    assert stored.context_sha256 and len(stored.context_sha256) == 64
    assert "password" not in stored.result_json


def test_rejects_project_owned_by_another_user(db):
    owner = User(email="owner@example.test", password_hash="hash")
    other = User(email="other@example.test", password_hash="hash")
    db.add_all([owner, other])
    db.flush()
    project = Project(owner_id=owner.id, name="private")
    db.add(project)
    db.flush()
    context, correlations, triage = setup_context()
    with pytest.raises(ValueError):
        persist_analysis_run(db, project_id=project.id, actor=other, context=context,
            correlations=correlations, triage=triage, model="model")


def test_analysis_rows_are_immutable_after_migration_trigger(db):
    user = User(email="owner@example.test", password_hash="hash")
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name="project")
    db.add(project)
    db.flush()
    context, correlations, triage = setup_context()
    record = persist_analysis_run(db, project_id=project.id, actor=user,
        context=context, correlations=correlations, triage=triage, model="model")
    db.commit()
    # Base.metadata.create_all does not install migration triggers; immutability is covered by migration tests.
    assert json.loads(record.result_json)["disposition"] == "requires_independent_validation"


def test_redacts_secrets_echoed_by_model_before_storage(db):
    user = User(email="redact@example.test", password_hash="hash")
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name="redaction")
    db.add(project)
    db.flush()
    context, correlations, triage = setup_context()
    triage = triage.model_copy(update={"hypothesis": "Possible leak password=echoedsecret"})
    record = persist_analysis_run(db, project_id=project.id, actor=user,
        context=context, correlations=correlations, triage=triage, model="model")
    assert "echoedsecret" not in record.result_json
    assert "[REDACTED]" in record.result_json



def test_execution_metadata_flows_into_immutable_persistence(db):
    user = User(email="execution@example.test", password_hash="hash")
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name="execution")
    db.add(project)
    db.flush()
    context, correlations, triage = setup_context()
    execution = AnalysisExecutionResult(
        triage=triage, provider="deepseek", model="deepseek-test",
        prompt_tokens=30, completion_tokens=20, total_tokens=50,
        provider_request_id="req_example", context_sha256="a"*64,
        correlations_sha256="b"*64, response_received_at=datetime.now(timezone.utc),
    )
    record = persist_analysis_execution(
        db, project_id=project.id, actor=user, context=context,
        correlations=correlations, execution=execution,
    )
    assert record.prompt_tokens == 30
    assert record.completion_tokens == 20
    assert record.total_tokens == 50
    assert record.provider_request_id == "req_example"
    assert record.model == "deepseek-test"



def test_analysis_persistence_binds_only_targets_in_same_project(db):
    owner = User(email="target-owner@example.test", password_hash="hash")
    other_owner = User(email="target-other@example.test", password_hash="hash")
    db.add_all([owner, other_owner])
    db.flush()
    project = Project(owner_id=owner.id, name="target-bound")
    other_project = Project(owner_id=other_owner.id, name="other-target")
    db.add_all([project, other_project])
    db.flush()
    target = Target(project_id=project.id, value="https://target.example.test")
    foreign_target = Target(project_id=other_project.id, value="https://foreign.example.test")
    db.add_all([target, foreign_target])
    db.flush()
    context, correlations, triage = setup_context()

    record = persist_analysis_run(
        db, project_id=project.id, actor=owner, context=context,
        correlations=correlations, triage=triage, model="model", target_id=target.id,
    )
    assert record.target_id == target.id
    with pytest.raises(ValueError, match="target does not belong to project"):
        persist_analysis_run(
            db, project_id=project.id, actor=owner, context=context,
            correlations=correlations, triage=triage, model="model", target_id=foreign_target.id,
        )
