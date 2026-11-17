"""Persist immutable, evidence-bound AI triage runs."""
from alembic import op
import sqlalchemy as sa

revision = "0012_ai_analysis_runs"
down_revision = "0011_worker_observation_immutability"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ai_analysis_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("context_sha256", sa.String(64), nullable=False),
        sa.Column("correlations_sha256", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(40), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("disposition", sa.String(50), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("total_tokens", sa.Integer(), nullable=True),
        sa.Column("cost_usd", sa.String(32), nullable=True),
        sa.Column("provider_request_id", sa.String(160), nullable=True),
        sa.Column("execution_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('completed')", name="ck_ai_analysis_run_status"),
        sa.CheckConstraint("disposition = 'requires_independent_validation'",
                           name="ck_ai_analysis_requires_validation"),
        sa.CheckConstraint("execution_enabled = false", name="ck_ai_analysis_execution_disabled"),
    )
    op.create_index("ix_ai_analysis_runs_project_id", "ai_analysis_runs", ["project_id"])
    op.create_index("ix_ai_analysis_runs_created_by", "ai_analysis_runs", ["created_by"])
    op.create_index("ix_ai_analysis_runs_context_sha256", "ai_analysis_runs", ["context_sha256"])
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("""
            CREATE TRIGGER ai_analysis_runs_no_update BEFORE UPDATE ON ai_analysis_runs
            BEGIN SELECT RAISE(ABORT, 'AI analysis runs are append-only'); END
        """)
        op.execute("""
            CREATE TRIGGER ai_analysis_runs_no_delete BEFORE DELETE ON ai_analysis_runs
            BEGIN SELECT RAISE(ABORT, 'AI analysis runs are append-only'); END
        """)
    elif bind.dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION reject_ai_analysis_run_mutation() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION 'AI analysis runs are append-only'; END;
            $$ LANGUAGE plpgsql
        """)
        op.execute("""
            CREATE TRIGGER ai_analysis_runs_no_mutation BEFORE UPDATE OR DELETE ON ai_analysis_runs
            FOR EACH ROW EXECUTE FUNCTION reject_ai_analysis_run_mutation()
        """)
    else:
        raise RuntimeError(f"AI analysis immutability is unsupported for {bind.dialect.name}")


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS ai_analysis_runs_no_update")
        op.execute("DROP TRIGGER IF EXISTS ai_analysis_runs_no_delete")
    elif bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS ai_analysis_runs_no_mutation ON ai_analysis_runs")
        op.execute("DROP FUNCTION IF EXISTS reject_ai_analysis_run_mutation()")
    op.drop_index("ix_ai_analysis_runs_context_sha256", table_name="ai_analysis_runs")
    op.drop_index("ix_ai_analysis_runs_created_by", table_name="ai_analysis_runs")
    op.drop_index("ix_ai_analysis_runs_project_id", table_name="ai_analysis_runs")
    op.drop_table("ai_analysis_runs")
