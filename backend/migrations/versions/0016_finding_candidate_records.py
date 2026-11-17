"""Persist immutable, unconfirmed finding candidates."""
from alembic import op
import sqlalchemy as sa

revision = "0016_finding_candidate_records"
down_revision = "0015_human_finding_decisions"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "finding_candidate_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analysis_run_id", sa.Integer(), sa.ForeignKey("ai_analysis_runs.id"), nullable=False),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("candidate_fingerprint", sa.String(64), nullable=False),
        sa.Column("qualification", sa.String(40), nullable=False),
        sa.Column("finding_status", sa.String(20), nullable=False),
        sa.Column("evidence_bundle_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_bundle_json", sa.Text(), nullable=False),
        sa.Column("qualification_json", sa.Text(), nullable=False),
        sa.Column("execution_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("analysis_run_id", "candidate_fingerprint", name="uq_finding_candidate_run_fingerprint"),
        sa.CheckConstraint("qualification = 'human_review_candidate'", name="ck_finding_candidate_reviewable_only"),
        sa.CheckConstraint("finding_status = 'unconfirmed'", name="ck_finding_candidate_unconfirmed_only"),
        sa.CheckConstraint("execution_enabled = false", name="ck_finding_candidate_execution_disabled"),
    )
    for column in ("analysis_run_id", "project_id", "created_by", "candidate_fingerprint"):
        op.create_index(f"ix_finding_candidate_records_{column}", "finding_candidate_records", [column])
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("""CREATE TRIGGER finding_candidate_records_no_update BEFORE UPDATE ON finding_candidate_records BEGIN SELECT RAISE(ABORT, 'finding candidate records are immutable'); END""")
        op.execute("""CREATE TRIGGER finding_candidate_records_no_delete BEFORE DELETE ON finding_candidate_records BEGIN SELECT RAISE(ABORT, 'finding candidate records are immutable'); END""")
    elif bind.dialect.name == "postgresql":
        op.execute("""CREATE FUNCTION reject_finding_candidate_mutation() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'finding candidate records are immutable'; END; $$ LANGUAGE plpgsql""")
        op.execute("""CREATE TRIGGER finding_candidate_records_no_mutation BEFORE UPDATE OR DELETE ON finding_candidate_records FOR EACH ROW EXECUTE FUNCTION reject_finding_candidate_mutation()""")
    else:
        raise RuntimeError(f"Candidate immutability is unsupported for {bind.dialect.name}")


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS finding_candidate_records_no_update")
        op.execute("DROP TRIGGER IF EXISTS finding_candidate_records_no_delete")
    elif bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS finding_candidate_records_no_mutation ON finding_candidate_records")
        op.execute("DROP FUNCTION IF EXISTS reject_finding_candidate_mutation()")
    for column in ("candidate_fingerprint", "created_by", "project_id", "analysis_run_id"):
        op.drop_index(f"ix_finding_candidate_records_{column}", table_name="finding_candidate_records")
    op.drop_table("finding_candidate_records")
