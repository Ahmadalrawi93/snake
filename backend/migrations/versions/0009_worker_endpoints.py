"""Add administratively provisioned, certificate-pinned worker endpoints."""
from alembic import op
import sqlalchemy as sa

revision = "0009_worker_endpoints"
down_revision = "0008_receipt_worker_binding"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "worker_endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=False),
        sa.Column("tls_server_name", sa.String(length=253), nullable=False),
        sa.Column("certificate_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("worker_id", name="uq_worker_endpoint_worker"),
        sa.CheckConstraint("status IN ('active', 'revoked')", name="ck_worker_endpoint_status"),
    )
    op.create_index("ix_worker_endpoints_worker_id", "worker_endpoints", ["worker_id"])
    op.create_index("ix_worker_endpoints_status", "worker_endpoints", ["status"])


def downgrade():
    op.drop_index("ix_worker_endpoints_status", table_name="worker_endpoints")
    op.drop_index("ix_worker_endpoints_worker_id", table_name="worker_endpoints")
    op.drop_table("worker_endpoints")
