"""Persist bounded local HTTP recon runs and redacted observations."""

from alembic import op
import sqlalchemy as sa

revision = "0026_local_recon_runs"
down_revision = "0025_auth_failed_attempt_buckets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "local_recon_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scope_snapshot_id", sa.Integer(), sa.ForeignKey("scope_snapshots.id"), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("pages_requested", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("execution_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.CheckConstraint(
            "status IN ('completed', 'partial', 'failed')",
            name="ck_local_recon_run_status",
        ),
        sa.CheckConstraint(
            "pages_requested >= 0 AND pages_requested <= 10",
            name="ck_local_recon_pages_requested",
        ),
        sa.CheckConstraint(
            "observation_count >= 0 AND observation_count <= 250",
            name="ck_local_recon_observation_count",
        ),
        sa.CheckConstraint(
            "execution_enabled = false",
            name="ck_local_recon_execution_disabled",
        ),
    )
    for column in ("project_id", "target_id", "scope_snapshot_id", "created_by"):
        op.create_index(f"ix_local_recon_runs_{column}", "local_recon_runs", [column])

    op.create_table(
        "local_recon_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("local_recon_runs.id"), nullable=False),
        sa.Column("observation_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("host_key", sa.String(length=253), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("classification", sa.String(length=40), nullable=False, server_default="unconfirmed_observation"),
        sa.UniqueConstraint("observation_id", name="uq_local_recon_observation_id"),
        sa.CheckConstraint(
            "kind IN ('url', 'http_header')",
            name="ck_local_recon_observation_kind",
        ),
        sa.CheckConstraint(
            "classification = 'unconfirmed_observation'",
            name="ck_local_recon_observation_unconfirmed",
        ),
    )
    op.create_index("ix_local_recon_observations_run_id", "local_recon_observations", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_local_recon_observations_run_id", table_name="local_recon_observations")
    op.drop_table("local_recon_observations")
    for column in ("created_by", "scope_snapshot_id", "target_id", "project_id"):
        op.drop_index(f"ix_local_recon_runs_{column}", table_name="local_recon_runs")
    op.drop_table("local_recon_runs")
