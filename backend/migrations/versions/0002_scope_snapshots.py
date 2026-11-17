"""Add explicit reviewed scope rules and immutable scope snapshots."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0002_scope"
down_revision = "0001_auth"
branch_labels = None
depends_on = None

def upgrade():
    bind = op.get_bind()
    auth_cols = {c["name"] for c in inspect(bind).get_columns("authorizations")}
    if "scope_rules" not in auth_cols:
        with op.batch_alter_table("authorizations") as batch:
            batch.add_column(sa.Column("scope_rules", sa.Text(), nullable=False, server_default="[]"))
    if "scope_snapshots" not in inspect(bind).get_table_names():
        op.create_table(
            "scope_snapshots",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
            sa.Column("authorization_id", sa.Integer(), sa.ForeignKey("authorizations.id"), nullable=False),
            sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("snapshot_json", sa.Text(), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.String(length=40), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_scope_snapshots_project_id", "scope_snapshots", ["project_id"])
        op.create_index("ix_scope_snapshots_target_id", "scope_snapshots", ["target_id"])
        op.create_index("ix_scope_snapshots_authorization_id", "scope_snapshots", ["authorization_id"])
        op.create_index("ix_scope_snapshots_sha256", "scope_snapshots", ["sha256"])

def downgrade():
    if "scope_snapshots" in inspect(op.get_bind()).get_table_names():
        op.drop_table("scope_snapshots")
    auth_cols = {c["name"] for c in inspect(op.get_bind()).get_columns("authorizations")}
    if "scope_rules" in auth_cols:
        with op.batch_alter_table("authorizations") as batch:
            batch.drop_column("scope_rules")
