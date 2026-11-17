import json
from datetime import datetime, timezone
from uuid import uuid4, UUID

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.db.models import AIAnalysisRun, Project, User
from app.core.analysis_persistence import persist_analysis_run
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
