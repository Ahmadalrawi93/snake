"""Add durable worker dispatch attempt history."""
from alembic import op
import sqlalchemy as sa

revision = "0007_worker_dispatch_attempts"
down_revision = "0006_worker_keys"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "worker_dispatch_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("task_id", sa.String(length=36),
                  sa.ForeignKey("worker_task_receipts.task_id"), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("envelope_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="started"),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("task_id", "attempt_number",
                            name="uq_worker_attempt_task_number"),
        sa.CheckConstraint(
            "status IN ('started', 'delivered', 'failed', 'unknown')",
            name="ck_worker_attempt_status",
        ),
    )
    op.create_index("ix_worker_dispatch_attempts_task_id",
                    "worker_dispatch_attempts", ["task_id"])


def downgrade():
    op.drop_index("ix_worker_dispatch_attempts_task_id",
                  table_name="worker_dispatch_attempts")
    op.drop_table("worker_dispatch_attempts")
