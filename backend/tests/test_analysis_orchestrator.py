from datetime import datetime, timezone
from uuid import UUID
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db.database import Base
from app.db.models import User, Project, AIAnalysisRun
from app.core.analysis_orchestrator import qualify_and_persist_candidate, _digest
from app.schemas.analysis_context import AnalysisContext
from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceItem


@pytest.fixture
def orchestration_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine, autoflush=False)()
    user = User(email="orchestrator@example.org", password_hash="test-hash")
    db.add(user)
    db.flush()
    project = Project(owner_id=user.id, name="Orchestrator tests")
    db.add(project)
    db.flush()
    yield db, user, project
    db.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def _context():
    return AnalysisContext(
        total_observations=0, unique_observations=0, duplicate_count=0,
        groups=[], ungrouped=[],
    )


def _bundle(digest):
    now = datetime.now(timezone.utc)
    return ValidationEvidenceBundle(
        strategy_id="auth_strategy", analysis_context_sha256=digest,
        items=[ValidationEvidenceItem(
            evidence_id=UUID("00000000-0000-4000-8000-000000000001"),
            evidence_type="other", relationship="context_only",
            statement="A contextual note recorded for this orchestration test",
            source_label="reviewer", observation_ids=[],
            recorded_at=now, human_attested=True,
        )],
        reviewed_at=now,
    )


def test_candidate_pipeline_rejects_context_digest_mismatch(orchestration_db):
    db, user, project = orchestration_db
    context = _context()
    run = AIAnalysisRun(
        project_id=project.id, created_by=user.id, context_sha256="a" * 64,
        correlations_sha256="b" * 64, provider="deepseek", model="test",
        status="completed", disposition="requires_independent_validation",
        result_json="{}", execution_enabled=False,
    )
    db.add(run)
    db.commit()
    with pytest.raises(ValueError, match="context does not match"):
        qualify_and_persist_candidate(
            db, analysis_run_id=run.id, strategy_id="auth_strategy",
            actor=user, context=context, bundle=_bundle("a" * 64),
        )


def test_candidate_pipeline_requires_strategy_from_persisted_run(orchestration_db):
    db, user, project = orchestration_db
    context = _context()
    run = AIAnalysisRun(
        project_id=project.id, created_by=user.id, context_sha256=_digest(context.model_dump(mode="json")),
        correlations_sha256="b" * 64, provider="deepseek", model="test",
        status="completed", disposition="requires_independent_validation",
        result_json="{}", execution_enabled=False,
    )
    db.add(run)
    db.commit()
    digest = run.context_sha256
    with pytest.raises(ValueError, match="no persisted validation strategy"):
        qualify_and_persist_candidate(
            db, analysis_run_id=run.id, strategy_id="auth_strategy",
            actor=user, context=context, bundle=_bundle(digest),
        )


def test_candidate_pipeline_rejects_cross_owner_analysis_run(orchestration_db):
    db, user, project = orchestration_db
    other = User(email="other-orchestrator@example.org", password_hash="test-hash")
    db.add(other)
    db.flush()
    run = AIAnalysisRun(
        project_id=project.id, created_by=user.id, context_sha256="a" * 64,
        correlations_sha256="b" * 64, provider="deepseek", model="test",
        status="completed", disposition="requires_independent_validation",
        result_json="{}", execution_enabled=False,
    )
    db.add(run)
    db.commit()
    with pytest.raises(LookupError, match="analysis run not found"):
        qualify_and_persist_candidate(
            db, analysis_run_id=run.id, strategy_id="auth_strategy",
            actor=other, context=_context(), bundle=_bundle("a" * 64),
        )
