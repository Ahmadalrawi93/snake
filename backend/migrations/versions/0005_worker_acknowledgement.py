"""Persist authenticated worker acknowledgement metadata."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0005_worker_ack"
down_revision = "0004_worker_receipts"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("worker_task_receipts")}
    if "acknowledgement_outcome" not in columns:
        op.add_column(
            "worker_task_receipts",
            sa.Column("acknowledgement_outcome", sa.String(length=20), nullable=True),
        )
    if "acknowledgement_worker_id" not in columns:
        op.add_column(
            "worker_task_receipts",
            sa.Column("acknowledgement_worker_id", sa.String(length=128), nullable=True),
        )
    if "acknowledgement_validated_at" not in columns:
        op.add_column(
            "worker_task_receipts",
            sa.Column("acknowledgement_validated_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade():
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("worker_task_receipts")}
    for name in (
        "acknowledgement_validated_at",
        "acknowledgement_worker_id",
        "acknowledgement_outcome",
    ):
        if name in columns:
            op.drop_column("worker_task_receipts", name)
