"""Persist evidence-bound, append-only finding impact assessments."""
from alembic import op
import sqlalchemy as sa

from app.core.finding_impact_guards import install_sqlite_finding_impact_guards

revision = "0022_finding_impact_assessments"
down_revision = "0021_investigation_memory_candidate_link"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "finding_impact_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("candidate_id", sa.Integer(), sa.ForeignKey("finding_candidate_records.id"), nullable=False),
        sa.Column("analysis_run_id", sa.Integer(), sa.ForeignKey("ai_analysis_runs.id"), nullable=False),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("reviewer_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("evidence_bundle_sha256", sa.String(64), nullable=False),
        sa.Column("claims_sha256", sa.String(64), nullable=False),
        sa.Column("assessment_sha256", sa.String(64), nullable=False),
        sa.Column("assessment_json", sa.Text(), nullable=False),
        sa.Column("final_severity", sa.String(20), nullable=False, server_default="not_assessed"),
        sa.Column("cvss_vector", sa.String(120), nullable=True),
        sa.Column("execution_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("candidate_id", "assessment_sha256", name="uq_finding_impact_candidate_digest"),
        sa.CheckConstraint("final_severity = 'not_assessed'", name="ck_finding_impact_final_severity_unassessed"),
        sa.CheckConstraint("cvss_vector IS NULL", name="ck_finding_impact_cvss_unassigned"),
        sa.CheckConstraint("execution_enabled = false", name="ck_finding_impact_execution_disabled"),
    )
    op.create_index("ix_finding_impact_assessments_candidate_id", "finding_impact_assessments", ["candidate_id"])
    op.create_index("ix_finding_impact_assessments_analysis_run_id", "finding_impact_assessments", ["analysis_run_id"])
    op.create_index("ix_finding_impact_assessments_project_id", "finding_impact_assessments", ["project_id"])
    op.create_index("ix_finding_impact_assessments_reviewer_id", "finding_impact_assessments", ["reviewer_id"])

    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        install_sqlite_finding_impact_guards(bind)
    elif bind.dialect.name == "postgresql":
        op.execute("""CREATE FUNCTION reject_finding_impact_assessment_mutation() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'finding impact assessments are immutable'; END; $$ LANGUAGE plpgsql""")
        op.execute("CREATE TRIGGER finding_impact_assessments_no_mutation BEFORE UPDATE OR DELETE ON finding_impact_assessments FOR EACH ROW EXECUTE FUNCTION reject_finding_impact_assessment_mutation()")
    else:
        raise RuntimeError(f"Append-only impact assessments unsupported for {bind.dialect.name}")


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS finding_impact_assessments_no_update")
        op.execute("DROP TRIGGER IF EXISTS finding_impact_assessments_no_delete")
    elif bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS finding_impact_assessments_no_mutation ON finding_impact_assessments")
        op.execute("DROP FUNCTION IF EXISTS reject_finding_impact_assessment_mutation()")
    op.drop_index("ix_finding_impact_assessments_reviewer_id", table_name="finding_impact_assessments")
    op.drop_index("ix_finding_impact_assessments_project_id", table_name="finding_impact_assessments")
    op.drop_index("ix_finding_impact_assessments_analysis_run_id", table_name="finding_impact_assessments")
    op.drop_index("ix_finding_impact_assessments_candidate_id", table_name="finding_impact_assessments")
    op.drop_table("finding_impact_assessments")
