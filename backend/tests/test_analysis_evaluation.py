from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.db.models import AIAnalysisRun, Project, User
from app.core.analysis_evaluation import record_human_evaluation, get_project_evaluation_metrics
from app.schemas.analysis_evaluations import AnalysisEvaluationCreate


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def setup_run(db, owner):
    project = Project(owner_id=owner.id, name="evaluation")
    db.add(project)
    db.flush()
    run = AIAnalysisRun(
        project_id=project.id, created_by=owner.id, context_sha256="a"*64,
        correlations_sha256="b"*64, provider="deepseek", model="test-model",
        status="completed", disposition="requires_independent_validation",
        result_json="{}", execution_enabled=False,
    )
    db.add(run)
    db.flush()
    return project, run


def test_human_outcomes_and_metrics_exclude_unresolved_from_precision(db):
    owner = User(email="owner@example.test", password_hash="hash")
    db.add(owner)
    db.flush()
    project, run = setup_run(db, owner)
    payloads = [
        AnalysisEvaluationCreate(outcome="confirmed", evidence_sha256="c"*64, validation_method="manual_reproduction"),
        AnalysisEvaluationCreate(outcome="false_positive", evidence_sha256="d"*64, validation_method="manual_reproduction"),
        AnalysisEvaluationCreate(outcome="inconclusive", validation_method="manual_review"),
        AnalysisEvaluationCreate(outcome="duplicate", validation_method="triage_review"),
    ]
    for payload in payloads:
        record_human_evaluation(db, analysis_run_id=run.id, actor=owner, payload=payload)
    db.commit()
    metrics = get_project_evaluation_metrics(db, project_id=project.id, actor=owner)
    assert metrics == {
        "reviewed": 4, "confirmed": 1, "false_positive": 1,
        "inconclusive": 1, "duplicate": 1,
        "resolved_precision": 0.5, "resolution_coverage": 0.5,
    }


def test_non_owner_cannot_evaluate_or_read_metrics(db):
    owner = User(email="owner@example.test", password_hash="hash")
    other = User(email="other@example.test", password_hash="hash")
    db.add_all([owner, other])
    db.flush()
    project, run = setup_run(db, owner)
    payload = AnalysisEvaluationCreate(outcome="confirmed", evidence_sha256="c"*64, validation_method="manual")
    with pytest.raises(LookupError):
        record_human_evaluation(db, analysis_run_id=run.id, actor=other, payload=payload)
    with pytest.raises(LookupError):
        get_project_evaluation_metrics(db, project_id=project.id, actor=other)


def test_resolved_outcomes_require_evidence_digest():
    with pytest.raises(ValueError):
        AnalysisEvaluationCreate(outcome="confirmed", validation_method="manual")
    with pytest.raises(ValueError):
        AnalysisEvaluationCreate(outcome="false_positive", evidence_sha256="not-a-hash", validation_method="manual")
