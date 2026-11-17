"""Append-only finding lifecycle and encrypted evidence vault."""
from alembic import op
import sqlalchemy as sa

revision = "0017_finding_lifecycle_evidence_vault"
down_revision = "0016_finding_candidate_records"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "finding_lifecycle_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("candidate_id", sa.Integer(), sa.ForeignKey("finding_candidate_records.id"), nullable=False),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("from_status", sa.String(32), nullable=False),
        sa.Column("to_status", sa.String(32), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("related_candidate_fingerprint", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("from_status IN ('new','under_review','needs_more_evidence','confirmed','rejected','duplicate')", name="ck_finding_lifecycle_from"),
        sa.CheckConstraint("to_status IN ('new','under_review','needs_more_evidence','confirmed','rejected','duplicate')", name="ck_finding_lifecycle_to"),
    )
    op.create_index("ix_finding_lifecycle_events_candidate_id", "finding_lifecycle_events", ["candidate_id"])
    op.create_table(
        "finding_evidence_artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("candidate_id", sa.Integer(), sa.ForeignKey("finding_candidate_records.id"), nullable=False),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("uploaded_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("filename", sa.String(180), nullable=False),
        sa.Column("media_type", sa.String(80), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("encrypted_content", sa.LargeBinary(), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("size_bytes > 0 AND size_bytes <= 1048576", name="ck_finding_evidence_size"),
    )
    op.create_index("ix_finding_evidence_candidate_id", "finding_evidence_artifacts", ["candidate_id"])
    op.create_index("ix_finding_evidence_project_id", "finding_evidence_artifacts", ["project_id"])
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        for table in ("finding_lifecycle_events", "finding_evidence_artifacts"):
            op.execute(f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT, '{table} are immutable'); END")
            op.execute(f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT, '{table} are immutable'); END")
    elif bind.dialect.name == "postgresql":
        op.execute("""CREATE FUNCTION reject_finding_lifecycle_vault_mutation() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'finding lifecycle and evidence records are immutable'; END; $$ LANGUAGE plpgsql""")
        for table in ("finding_lifecycle_events", "finding_evidence_artifacts"):
            op.execute(f"CREATE TRIGGER {table}_no_mutation BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION reject_finding_lifecycle_vault_mutation()")
    else:
        raise RuntimeError(f"Append-only records unsupported for {bind.dialect.name}")


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        for table in ("finding_lifecycle_events", "finding_evidence_artifacts"):
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_update")
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_delete")
    elif bind.dialect.name == "postgresql":
        for table in ("finding_lifecycle_events", "finding_evidence_artifacts"):
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_mutation ON {table}")
        op.execute("DROP FUNCTION IF EXISTS reject_finding_lifecycle_vault_mutation()")
    op.drop_index("ix_finding_evidence_project_id", table_name="finding_evidence_artifacts")
    op.drop_index("ix_finding_evidence_candidate_id", table_name="finding_evidence_artifacts")
    op.drop_table("finding_evidence_artifacts")
    op.drop_index("ix_finding_lifecycle_events_candidate_id", table_name="finding_lifecycle_events")
    op.drop_table("finding_lifecycle_events")
