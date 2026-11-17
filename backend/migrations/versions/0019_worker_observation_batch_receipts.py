"""Add idempotent receipts for signed worker observation batches."""
from alembic import op
import sqlalchemy as sa

revision = "0019_worker_observation_batch_receipts"
down_revision = "0018_analysis_observation_provenance"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "worker_observation_batch_receipts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("task_id", sa.String(length=36), sa.ForeignKey("worker_task_receipts.task_id"), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("envelope_sha256", sa.String(length=64), nullable=False),
        sa.Column("batch_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=128), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("task_id", name="uq_worker_observation_batch_task"),
        sa.CheckConstraint("observation_count >= 0 AND observation_count <= 500", name="ck_worker_batch_observation_count"),
    )


def downgrade():
    op.drop_table("worker_observation_batch_receipts")
