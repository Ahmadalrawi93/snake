"""Prevent mutation or deletion of persisted worker observations."""
from alembic import op

revision = "0011_worker_observation_immutability"
down_revision = "0010_worker_observations"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("""
            CREATE TRIGGER worker_observations_no_update
            BEFORE UPDATE ON worker_observations
            BEGIN
                SELECT RAISE(ABORT, 'worker observations are append-only');
            END
        """)
        op.execute("""
            CREATE TRIGGER worker_observations_no_delete
            BEFORE DELETE ON worker_observations
            BEGIN
                SELECT RAISE(ABORT, 'worker observations are append-only');
            END
        """)
    elif bind.dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION reject_worker_observation_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'worker observations are append-only';
            END;
            $$ LANGUAGE plpgsql
        """)
        op.execute("""
            CREATE TRIGGER worker_observations_no_mutation
            BEFORE UPDATE OR DELETE ON worker_observations
            FOR EACH ROW EXECUTE FUNCTION reject_worker_observation_mutation()
        """)
    else:
        raise RuntimeError(
            f"append-only worker observations are not implemented for {bind.dialect.name}"
        )


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS worker_observations_no_update")
        op.execute("DROP TRIGGER IF EXISTS worker_observations_no_delete")
    elif bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS worker_observations_no_mutation ON worker_observations")
        op.execute("DROP FUNCTION IF EXISTS reject_worker_observation_mutation()")
