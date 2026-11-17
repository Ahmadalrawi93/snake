"""Persist signed worker observations separately from vulnerability findings."""
from alembic import op
import sqlalchemy as sa

revision = "0010_worker_observations"
down_revision = "0009_worker_endpoints"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "worker_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("observation_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36), sa.ForeignKey("worker_task_receipts.task_id"), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("envelope_sha256", sa.String(length=64), nullable=False),
        sa.Column("batch_sha256", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("classification", sa.String(length=40), nullable=False, server_default="unconfirmed_observation"),
        sa.UniqueConstraint("observation_id", name="uq_worker_observation_external_id"),
        sa.CheckConstraint(
            "kind IN ('hostname', 'url', 'ip', 'technology', 'http_header', 'dns_record')",
            name="ck_worker_observation_kind",
        ),
        sa.CheckConstraint(
            "classification = 'unconfirmed_observation'",
            name="ck_worker_observation_unconfirmed_only",
        ),
    )
    op.create_index("ix_worker_observations_task_id", "worker_observations", ["task_id"])
    op.create_index("ix_worker_observations_worker_id", "worker_observations", ["worker_id"])
    op.create_index("ix_worker_observations_kind", "worker_observations", ["kind"])


def downgrade():
    op.drop_index("ix_worker_observations_kind", table_name="worker_observations")
    op.drop_index("ix_worker_observations_worker_id", table_name="worker_observations")
    op.drop_index("ix_worker_observations_task_id", table_name="worker_observations")
    op.drop_table("worker_observations")
