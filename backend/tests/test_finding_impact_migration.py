"""Integration checks for the finding impact Alembic revision."""
import importlib.util
from pathlib import Path

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
