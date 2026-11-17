"""Add users and project ownership; safe for fresh and legacy SQLite databases."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0001_auth"
down_revision = "0000_core_schema"
branch_labels = None
depends_on = None

def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = inspector.get_table_names()
    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("email", sa.String(length=320), nullable=False, unique=True),
            sa.Column("password_hash", sa.String(length=512), nullable=False),
            sa.Column("role", sa.String(length=20), nullable=False, server_default="user"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    inspector = inspect(bind)
    project_columns = {c["name"] for c in inspector.get_columns("projects")}
    if "owner_id" not in project_columns:
        with op.batch_alter_table("projects") as batch:
            batch.add_column(sa.Column("owner_id", sa.Integer(), nullable=True))
            batch.create_foreign_key("fk_projects_owner_id_users", "users", ["owner_id"], ["id"])
    project_indexes = {index["name"] for index in inspect(bind).get_indexes("projects")}
    if "ix_projects_owner_id" not in project_indexes:
        op.create_index("ix_projects_owner_id", "projects", ["owner_id"])
    audit_columns = {c["name"] for c in inspect(bind).get_columns("audit_events")}
    if "actor_user_id" not in audit_columns:
        with op.batch_alter_table("audit_events") as batch:
            batch.add_column(sa.Column("actor_user_id", sa.Integer(), nullable=True))
            batch.create_foreign_key("fk_audit_actor_user_id_users", "users", ["actor_user_id"], ["id"])
    audit_indexes = {index["name"] for index in inspect(bind).get_indexes("audit_events")}
    if "ix_audit_events_actor_user_id" not in audit_indexes:
        op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"])

def downgrade():
    bind = op.get_bind()
    audit_fks = {fk.get("name") for fk in inspect(bind).get_foreign_keys("audit_events")}
    if "actor_user_id" in {c["name"] for c in inspect(bind).get_columns("audit_events")}:
        with op.batch_alter_table("audit_events") as batch:
            if "fk_audit_actor_user_id_users" in audit_fks:
                batch.drop_constraint("fk_audit_actor_user_id_users", type_="foreignkey")
            batch.drop_column("actor_user_id")
    project_fks = {fk.get("name") for fk in inspect(bind).get_foreign_keys("projects")}
    if "owner_id" in {c["name"] for c in inspect(bind).get_columns("projects")}:
        with op.batch_alter_table("projects") as batch:
            if "fk_projects_owner_id_users" in project_fks:
                batch.drop_constraint("fk_projects_owner_id_users", type_="foreignkey")
            batch.drop_column("owner_id")
    if "users" in inspect(bind).get_table_names():
        op.drop_table("users")
