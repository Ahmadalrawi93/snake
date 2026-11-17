"""Persist append-only, owner-scoped human finding decisions."""
from alembic import op
import sqlalchemy as sa

revision = "0014_human_finding_decisions"
down_revision = "0013_ai_analysis_evaluations"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "human_finding_decisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analysis_run_id", sa.Integer(), sa.ForeignKey("ai_analysis_runs.id"), nullable=False),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("evaluator_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("candidate_fingerprint", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=True),
        sa.Column("validation_method", sa.String(80), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("reviewer_attested", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "analysis_run_id", "candidate_fingerprint", "evaluator_id",
            name="uq_human_finding_decision_reviewer_candidate",
        ),
        sa.CheckConstraint(
            "outcome IN ('confirmed', 'false_positive', 'inconclusive', 'duplicate')",
            name="ck_human_finding_decision_outcome",
        ),
        sa.CheckConstraint(
            "(outcome IN ('confirmed', 'false_positive') AND evidence_sha256 IS NOT NULL) OR "
            "(outcome IN ('inconclusive', 'duplicate'))",
            name="ck_human_finding_decision_evidence",
        ),
        sa.CheckConstraint("reviewer_attested = true", name="ck_human_finding_reviewer_attested"),
    )
    for column in ("analysis_run_id", "project_id", "evaluator_id", "candidate_fingerprint"):
        op.create_index(
            f"ix_human_finding_decisions_{column}", "human_finding_decisions", [column]
        )
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("""
            CREATE TRIGGER human_finding_decisions_no_update BEFORE UPDATE ON human_finding_decisions
            BEGIN SELECT RAISE(ABORT, 'human finding decisions are append-only'); END
        """)
        op.execute("""
            CREATE TRIGGER human_finding_decisions_no_delete BEFORE DELETE ON human_finding_decisions
            BEGIN SELECT RAISE(ABORT, 'human finding decisions are append-only'); END
        """)
    elif bind.dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION reject_human_finding_decision_mutation() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION 'human finding decisions are append-only'; END;
            $$ LANGUAGE plpgsql
        """)
        op.execute("""
            CREATE TRIGGER human_finding_decisions_no_mutation
            BEFORE UPDATE OR DELETE ON human_finding_decisions
            FOR EACH ROW EXECUTE FUNCTION reject_human_finding_decision_mutation()
        """)
    else:
        raise RuntimeError(f"Finding decision immutability is unsupported for {bind.dialect.name}")


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS human_finding_decisions_no_update")
        op.execute("DROP TRIGGER IF EXISTS human_finding_decisions_no_delete")
    elif bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS human_finding_decisions_no_mutation ON human_finding_decisions")
        op.execute("DROP FUNCTION IF EXISTS reject_human_finding_decision_mutation()")
    for column in ("candidate_fingerprint", "evaluator_id", "project_id", "analysis_run_id"):
        op.drop_index(f"ix_human_finding_decisions_{column}", table_name="human_finding_decisions")
    op.drop_table("human_finding_decisions")
