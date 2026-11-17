"""Integration checks for the finding impact Alembic revision."""
import importlib.util
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect, text

from app.db.database import Base
from app.db import models  # noqa: F401


def _load_revision():
    revision_path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "0022_finding_impact_assessments.py"
    )
    spec = importlib.util.spec_from_file_location(
        "migration_0022_finding_impact_assessments", revision_path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_revision_0022_installs_and_removes_sqlite_immutability_guards():
    engine = create_engine("sqlite://")
    impact_table = Base.metadata.tables["finding_impact_assessments"]
    prerequisite_tables = [
        table for table in Base.metadata.sorted_tables if table is not impact_table
    ]
    with engine.begin() as connection:
        Base.metadata.create_all(bind=connection, tables=prerequisite_tables)
        revision = _load_revision()
        with Operations.context(MigrationContext.configure(connection)):
            revision.upgrade()

        trigger_names = {
            row[0]
            for row in connection.execute(text(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            ))
        }
        assert "finding_impact_assessments_no_update" in trigger_names
        assert "finding_impact_assessments_no_delete" in trigger_names
        assert "finding_impact_assessments" in inspect(connection).get_table_names()

        connection.execute(text("""
            INSERT INTO finding_impact_assessments (
                id, candidate_id, analysis_run_id, project_id, reviewer_id,
                evidence_bundle_sha256, claims_sha256, assessment_sha256,
                assessment_json, final_severity, cvss_vector, execution_enabled,
                created_at
            ) VALUES (
                1, 1, 1, 1, 1, :evidence, :claims, :assessment,
                '{}', 'not_assessed', NULL, 0, CURRENT_TIMESTAMP
            )
        """), {
            "evidence": "a" * 64,
            "claims": "b" * 64,
            "assessment": "c" * 64,
        })
        with pytest.raises(IntegrityError):
            connection.execute(text(
                "UPDATE finding_impact_assessments SET assessment_json = '{}' WHERE id = 1"
            ))
        with pytest.raises(IntegrityError):
            connection.execute(text(
                "DELETE FROM finding_impact_assessments WHERE id = 1"
            ))

        with Operations.context(MigrationContext.configure(connection)):
            revision.downgrade()

        remaining = {
            row[0]
            for row in connection.execute(text(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            ))
        }
        assert "finding_impact_assessments_no_update" not in remaining
        assert "finding_impact_assessments_no_delete" not in remaining
        assert "finding_impact_assessments" not in inspect(connection).get_table_names()
    engine.dispose()
