"""Persist failed authentication counters without storing email addresses."""

from alembic import op
import sqlalchemy as sa

revision = "0025_auth_failed_attempt_buckets"
down_revision = "0024_revocable_api_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_failed_attempt_buckets",
        sa.Column("key_sha256", sa.String(length=64), primary_key=True),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(key_sha256) = 64", name="ck_auth_failed_bucket_digest_length"),
        sa.CheckConstraint("attempts >= 1", name="ck_auth_failed_attempts_positive"),
    )
    op.create_index(
        "ix_auth_failed_attempt_buckets_updated_at",
        "auth_failed_attempt_buckets",
        ["updated_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_auth_failed_attempt_buckets_updated_at", table_name="auth_failed_attempt_buckets")
    op.drop_table("auth_failed_attempt_buckets")
