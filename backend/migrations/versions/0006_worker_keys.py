"""Create the registered worker public-key trust store."""
from alembic import op
import sqlalchemy as sa

revision = "0006_worker_keys"
down_revision = "0005_worker_ack"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "worker_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("public_key_b64", sa.String(length=2048), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("worker_id", "key_id", name="uq_worker_keys_worker_key"),
        sa.UniqueConstraint("fingerprint_sha256", name="uq_worker_keys_fingerprint"),
        sa.CheckConstraint("status IN ('active', 'revoked')", name="ck_worker_keys_status"),
    )
    op.create_index("ix_worker_keys_worker_id", "worker_keys", ["worker_id"])
    op.create_index("ix_worker_keys_status", "worker_keys", ["status"])


def downgrade():
    op.drop_index("ix_worker_keys_status", table_name="worker_keys")
    op.drop_index("ix_worker_keys_worker_id", table_name="worker_keys")
    op.drop_table("worker_keys")
