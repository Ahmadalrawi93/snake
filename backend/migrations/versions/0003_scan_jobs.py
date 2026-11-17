"""Add queued scan job records (execution remains disabled)."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0003_scan_jobs"
down_revision = "0002_scope"
branch_labels = None
depends_on = None


def upgrade():
    if "scan_jobs" not in inspect(op.get_bind()).get_table_names():
        op.create_table(
            "scan_jobs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
            sa.Column("scope_snapshot_id", sa.Integer(), sa.ForeignKey("scope_snapshots.id"), nullable=False),
            sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("profile", sa.String(length=40), nullable=False, server_default="passive_recon"),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
            sa.Column("execution_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_scan_jobs_project_id", "scan_jobs", ["project_id"])
        op.create_index("ix_scan_jobs_target_id", "scan_jobs", ["target_id"])
        op.create_index("ix_scan_jobs_scope_snapshot_id", "scan_jobs", ["scope_snapshot_id"])
        op.create_index("ix_scan_jobs_created_by", "scan_jobs", ["created_by"])
        op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])


def downgrade():
    if "scan_jobs" in inspect(op.get_bind()).get_table_names():
        op.drop_table("scan_jobs")
