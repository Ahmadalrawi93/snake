"""Add users and project ownership."""
from alembic import op
import sqlalchemy as sa

revision = "0001_auth"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False, server_default="user"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column("projects", sa.Column("owner_id", sa.Integer(), nullable=True))
    op.create_foreign_key("fk_projects_owner_id_users", "projects", "users", ["owner_id"], ["id"])
    op.add_column("audit_events", sa.Column("actor_user_id", sa.Integer(), nullable=True))
    op.create_foreign_key("fk_audit_actor_user_id_users", "audit_events", "users", ["actor_user_id"], ["id"])

def downgrade():
    op.drop_constraint("fk_audit_actor_user_id_users", "audit_events", type_="foreignkey")
    op.drop_column("audit_events", "actor_user_id")
    op.drop_constraint("fk_projects_owner_id_users", "projects", type_="foreignkey")
    op.drop_column("projects", "owner_id")
    op.drop_table("users")
