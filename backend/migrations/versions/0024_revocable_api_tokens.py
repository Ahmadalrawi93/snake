"""Add revocable API bearer token records."""

from alembic import op
import sqlalchemy as sa

revision = "0024_revocable_api_tokens"
down_revision = "0023_revocable_user_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_access_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_id_sha256", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("token_id_sha256", name="uq_api_access_tokens_token_digest"),
        sa.CheckConstraint("length(token_id_sha256) = 64", name="ck_api_access_tokens_token_digest_length"),
    )
    op.create_index("ix_api_access_tokens_user_id", "api_access_tokens", ["user_id"])
    op.create_index("ix_api_access_tokens_expires_at", "api_access_tokens", ["expires_at"])
    op.create_index("ix_api_access_tokens_revoked_at", "api_access_tokens", ["revoked_at"])


def downgrade() -> None:
    op.drop_index("ix_api_access_tokens_revoked_at", table_name="api_access_tokens")
    op.drop_index("ix_api_access_tokens_expires_at", table_name="api_access_tokens")
    op.drop_index("ix_api_access_tokens_user_id", table_name="api_access_tokens")
    op.drop_table("api_access_tokens")
