"""Database-level guards for append-only finding impact assessments."""

def install_sqlite_finding_impact_guards(connection) -> None:
    """Install the same SQLite mutation guards used by Alembic revision 0022."""
    connection.exec_driver_sql(
        "CREATE TRIGGER IF NOT EXISTS finding_impact_assessments_no_update "
        "BEFORE UPDATE ON finding_impact_assessments BEGIN "
        "SELECT RAISE(ABORT, 'finding impact assessments are immutable'); END"
    )
    connection.exec_driver_sql(
        "CREATE TRIGGER IF NOT EXISTS finding_impact_assessments_no_delete "
        "BEFORE DELETE ON finding_impact_assessments BEGIN "
        "SELECT RAISE(ABORT, 'finding impact assessments are immutable'); END"
    )
