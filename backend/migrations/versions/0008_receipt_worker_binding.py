"""Bind task receipts to the worker identity selected at signing time."""
from alembic import op
import sqlalchemy as sa

revision = "0008_receipt_worker_binding"
down_revision = "0007_worker_dispatch_attempts"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "worker_task_receipts",
        sa.Column("worker_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "worker_task_receipts",
        sa.Column("key_id", sa.String(length=128), nullable=True),
    )


def downgrade():
    op.drop_column("worker_task_receipts", "key_id")
    op.drop_column("worker_task_receipts", "worker_id")
