import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.db.models import AIAnalysisEvaluation, AIAnalysisRun, Project, User
from app.core.intelligence_feedback import build_intelligence_feedback_profile, _hypothesis_fingerprint


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def _add_run(db, project, owner, outcome, hypothesis, category="authorization"):
    run = AIAnalysisRun(
        project_id=project.id, created_by=owner.id, context_sha256="a"*64,
        correlations_sha256="b"*64, provider="deepseek", model="test-model",
        status="completed", disposition="requires_independent_validation",
        result_json=json.dumps({"category": category, "hypothesis": hypothesis}),
        execution_enabled=False,
    )
    db.add(run)
    db.flush()
    db.add(AIAnalysisEvaluation(
        analysis_run_id=run.id, project_id=project.id, evaluator_id=owner.id,
        outcome=outcome, evidence_sha256=("c"*64 if outcome in {"confirmed", "false_positive"} else None),
        validation_method="manual_review", notes="",
    ))


def test_profile_uses_only_human_evaluations_and_is_deterministic(db):
    owner = User(email="profile-owner@example.test", password_hash="hash")
    db.add(owner)
    db.flush()
    project = Project(owner_id=owner.id, name="feedback")
    db.add(project)
    db.flush()
    # Unreviewed run must not contribute to the profile.
    db.add(AIAnalysisRun(
        project_id=project.id, created_by=owner.id, context_sha256="d"*64,
        correlations_sha256="e"*64, provider="deepseek", model="test-model",
        status="completed", disposition="requires_independent_validation",
        result_json=json.dumps({"category": "authorization", "hypothesis": "unreviewed IDOR"}),
        execution_enabled=False,
    ))
    for _ in range(3):
        _add_run(db, project, owner, "false_positive", "Potential IDOR on /api/users/123")
    _add_run(db, project, owner, "inconclusive", "Potential IDOR on /api/users/456")
    db.commit()

    first = build_intelligence_feedback_profile(db, project_id=project.id, actor=owner)
    second = build_intelligence_feedback_profile(db, project_id=project.id, actor=owner)
    assert first.model_dump() == second.model_dump()
    assert first.evaluated_runs == 4
    assert len(first.patterns) == 1
    assert first.patterns[0].false_positive == 3
    assert first.patterns[0].inconclusive == 1
    assert first.patterns[0].confirmed == 0
    assert first.patterns[0].recommendation == "deprioritize"
    assert first.patterns[0].resolved_precision == 0.0


def test_confirmed_example_prevents_deprioritization(db):
    owner = User(email="profile-confirmed@example.test", password_hash="hash")
    db.add(owner)
    db.flush()
    project = Project(owner_id=owner.id, name="feedback")
    db.add(project)
    db.flush()
    for outcome in ["false_positive", "false_positive", "false_positive", "confirmed"]:
        _add_run(db, project, owner, outcome, "Potential access control weakness")
    db.commit()
    profile = build_intelligence_feedback_profile(db, project_id=project.id, actor=owner)
    assert profile.patterns[0].recommendation == "retain"
    assert profile.patterns[0].confirmed == 1


def test_project_isolation_and_owner_enforcement(db):
    owner = User(email="profile-a@example.test", password_hash="hash")
    other = User(email="profile-b@example.test", password_hash="hash")
    db.add_all([owner, other])
    db.flush()
    project = Project(owner_id=owner.id, name="private")
    db.add(project)
    db.flush()
    _add_run(db, project, owner, "false_positive", "Weak hypothesis")
    db.commit()
    with pytest.raises(LookupError):
        build_intelligence_feedback_profile(db, project_id=project.id, actor=other)


def test_fingerprint_normalizes_numeric_path_ids_but_keeps_category():
    a = _hypothesis_fingerprint("authorization", "Potential IDOR at /api/users/123")
    b = _hypothesis_fingerprint("authorization", "Potential IDOR at /api/users/456")
    c = _hypothesis_fingerprint("authentication", "Potential IDOR at /api/users/456")
    assert a == b
    assert a != c


def test_unresolved_labels_are_not_counted_as_negative_or_positive(db):
    owner = User(email="profile-unresolved@example.test", password_hash="hash")
    db.add(owner)
    db.flush()
    project = Project(owner_id=owner.id, name="feedback")
    db.add(project)
    db.flush()
    _add_run(db, project, owner, "inconclusive", "Unresolved hypothesis")
    _add_run(db, project, owner, "duplicate", "Unresolved hypothesis")
    db.commit()
    profile = build_intelligence_feedback_profile(db, project_id=project.id, actor=owner)
    item = profile.patterns[0]
    assert item.confirmed == item.false_positive == 0
    assert item.resolved_precision is None
    assert item.recommendation == "insufficient_evidence"



def test_multiple_reviewers_of_one_run_count_as_one_pattern_sample(db):
    owner = User(email="profile-multi-review@example.test", password_hash="hash")
    reviewer = User(email="profile-second-review@example.test", password_hash="hash")
    db.add_all([owner, reviewer])
    db.flush()
    project = Project(owner_id=owner.id, name="feedback")
    db.add(project)
    db.flush()
    run = AIAnalysisRun(
        project_id=project.id, created_by=owner.id, context_sha256="a"*64,
        correlations_sha256="b"*64, provider="deepseek", model="test-model",
        status="completed", disposition="requires_independent_validation",
        result_json=json.dumps({"category": "authorization", "hypothesis": "Potential IDOR"}),
        execution_enabled=False,
    )
    db.add(run)
    db.flush()
    for actor, outcome in [(owner, "false_positive"), (reviewer, "false_positive")]:
        db.add(AIAnalysisEvaluation(
            analysis_run_id=run.id, project_id=project.id, evaluator_id=actor.id,
            outcome=outcome, evidence_sha256="c"*64,
            validation_method="manual_review", notes="",
        ))
    db.commit()
    profile = build_intelligence_feedback_profile(db, project_id=project.id, actor=owner)
    assert profile.evaluated_runs == 1
    assert profile.patterns[0].reviewed == 1
    assert profile.patterns[0].false_positive == 1
    assert profile.patterns[0].recommendation == "insufficient_evidence"
