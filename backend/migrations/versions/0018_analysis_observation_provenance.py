"""Bind analysis runs to immutable worker observation provenance."""
from alembic import op
import sqlalchemy as sa

revision = "0018_analysis_observation_provenance"
down_revision = "0017_finding_lifecycle_evidence_vault"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("ai_analysis_runs") as batch:
        batch.add_column(sa.Column("provenance_sha256", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("source_observation_count", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("ix_ai_analysis_runs_provenance_sha256", "ai_analysis_runs", ["provenance_sha256"])
    op.create_table(
        "analysis_run_observation_links",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analysis_run_id", sa.Integer(), sa.ForeignKey("ai_analysis_runs.id"), nullable=False),
        sa.Column("observation_record_id", sa.Integer(), sa.ForeignKey("worker_observations.id"), nullable=False),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("envelope_sha256", sa.String(length=64), nullable=False),
        sa.Column("batch_sha256", sa.String(length=64), nullable=False),
        sa.Column("scope_snapshot_id", sa.Integer(), sa.ForeignKey("scope_snapshots.id"), nullable=False),
        sa.Column("scope_snapshot_sha256", sa.String(length=64), nullable=False),
        sa.Column("authorization_id", sa.Integer(), sa.ForeignKey("authorizations.id"), nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("analysis_run_id", "observation_record_id", name="uq_analysis_run_observation_link"),
    )
    for col in ("analysis_run_id", "observation_record_id", "project_id", "target_id", "task_id"):
        op.create_index(f"ix_analysis_run_observation_links_{col}", "analysis_run_observation_links", [col])
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("""CREATE TRIGGER analysis_run_observation_links_no_update BEFORE UPDATE ON analysis_run_observation_links BEGIN SELECT RAISE(ABORT, 'analysis provenance links are immutable'); END""")
        op.execute("""CREATE TRIGGER analysis_run_observation_links_no_delete BEFORE DELETE ON analysis_run_observation_links BEGIN SELECT RAISE(ABORT, 'analysis provenance links are immutable'); END""")
    elif bind.dialect.name == "postgresql":
        op.execute("""CREATE FUNCTION reject_analysis_provenance_mutation() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'analysis provenance links are immutable'; END; $$ LANGUAGE plpgsql""")
        op.execute("""CREATE TRIGGER analysis_run_observation_links_no_mutation BEFORE UPDATE OR DELETE ON analysis_run_observation_links FOR EACH ROW EXECUTE FUNCTION reject_analysis_provenance_mutation()""")
    else:
        raise RuntimeError(f"Analysis provenance immutability unsupported for {bind.dialect.name}")


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS analysis_run_observation_links_no_update")
        op.execute("DROP TRIGGER IF EXISTS analysis_run_observation_links_no_delete")
    elif bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS analysis_run_observation_links_no_mutation ON analysis_run_observation_links")
        op.execute("DROP FUNCTION IF EXISTS reject_analysis_provenance_mutation()")
    for col in ("task_id", "target_id", "project_id", "observation_record_id", "analysis_run_id"):
        op.drop_index(f"ix_analysis_run_observation_links_{col}", table_name="analysis_run_observation_links")
    op.drop_table("analysis_run_observation_links")
    op.drop_index("ix_ai_analysis_runs_provenance_sha256", table_name="ai_analysis_runs")
    with op.batch_alter_table("ai_analysis_runs") as batch:
        batch.drop_column("source_observation_count")
        batch.drop_column("provenance_sha256")
