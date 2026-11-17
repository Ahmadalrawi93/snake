"""Persist append-only human evaluations of AI analysis hypotheses."""
from alembic import op
import sqlalchemy as sa

revision = "0013_ai_analysis_evaluations"
down_revision = "0012_ai_analysis_runs"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ai_analysis_evaluations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analysis_run_id", sa.Integer(), sa.ForeignKey("ai_analysis_runs.id"), nullable=False),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("evaluator_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=True),
        sa.Column("validation_method", sa.String(80), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('confirmed', 'false_positive', 'inconclusive', 'duplicate')",
            name="ck_ai_analysis_evaluation_outcome",
        ),
        sa.CheckConstraint(
            "(outcome IN ('confirmed', 'false_positive') AND evidence_sha256 IS NOT NULL) OR "
            "(outcome IN ('inconclusive', 'duplicate'))",
            name="ck_ai_analysis_evaluation_evidence",
        ),
    )
    for column in ("analysis_run_id", "project_id", "evaluator_id"):
        op.create_index(f"ix_ai_analysis_evaluations_{column}", "ai_analysis_evaluations", [column])
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("""
            CREATE TRIGGER ai_analysis_evaluations_no_update BEFORE UPDATE ON ai_analysis_evaluations
            BEGIN SELECT RAISE(ABORT, 'AI analysis evaluations are append-only'); END
        """)
        op.execute("""
            CREATE TRIGGER ai_analysis_evaluations_no_delete BEFORE DELETE ON ai_analysis_evaluations
            BEGIN SELECT RAISE(ABORT, 'AI analysis evaluations are append-only'); END
        """)
    elif bind.dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION reject_ai_analysis_evaluation_mutation() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION 'AI analysis evaluations are append-only'; END;
            $$ LANGUAGE plpgsql
        """)
        op.execute("""
            CREATE TRIGGER ai_analysis_evaluations_no_mutation BEFORE UPDATE OR DELETE ON ai_analysis_evaluations
            FOR EACH ROW EXECUTE FUNCTION reject_ai_analysis_evaluation_mutation()
        """)
    else:
        raise RuntimeError(f"Evaluation immutability is unsupported for {bind.dialect.name}")


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS ai_analysis_evaluations_no_update")
        op.execute("DROP TRIGGER IF EXISTS ai_analysis_evaluations_no_delete")
    elif bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS ai_analysis_evaluations_no_mutation ON ai_analysis_evaluations")
        op.execute("DROP FUNCTION IF EXISTS reject_ai_analysis_evaluation_mutation()")
    for column in ("evaluator_id", "project_id", "analysis_run_id"):
        op.drop_index(f"ix_ai_analysis_evaluations_{column}", table_name="ai_analysis_evaluations")
    op.drop_table("ai_analysis_evaluations")
