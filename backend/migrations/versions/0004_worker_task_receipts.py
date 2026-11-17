"""Add durable one-time worker task receipts."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0004_worker_receipts"
down_revision = "0003_scan_jobs"
branch_labels = None
depends_on = None


def upgrade():
    if "worker_task_receipts" not in inspect(op.get_bind()).get_table_names():
        op.create_table(
            "worker_task_receipts",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("task_id", sa.String(length=36), nullable=False, unique=True),
            sa.Column("job_id", sa.Integer(), sa.ForeignKey("scan_jobs.id"), nullable=False, unique=True),
            sa.Column("envelope_sha256", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_worker_task_receipts_expires_at", "worker_task_receipts", ["expires_at"])


def downgrade():
    if "worker_task_receipts" in inspect(op.get_bind()).get_table_names():
        op.drop_table("worker_task_receipts")
