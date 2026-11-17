"""Persist project and target scoped investigation memory."""
from alembic import op
import sqlalchemy as sa

revision = "0020_investigation_memory"
down_revision = "0019_worker_observation_batch_receipts"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "investigation_memory_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("analysis_run_id", sa.Integer(), sa.ForeignKey("ai_analysis_runs.id"), nullable=False),
        sa.Column("strategy_id", sa.String(80), nullable=False),
        sa.Column("hypothesis_fingerprint", sa.String(64), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("hypothesis_text", sa.String(1000), nullable=False),
        sa.Column("observation_ids_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("execution_enabled", sa.Boolean(), nullable=False),
        sa.UniqueConstraint("analysis_run_id", "strategy_id", name="uq_investigation_memory_run_strategy"),
        sa.CheckConstraint("execution_enabled = false", name="ck_investigation_memory_execution_disabled"),
    )
    for column in ("project_id", "target_id", "analysis_run_id", "hypothesis_fingerprint"):
        op.create_index(f"ix_investigation_memory_records_{column}", "investigation_memory_records", [column])

def downgrade():
    for column in ("hypothesis_fingerprint", "analysis_run_id", "target_id", "project_id"):
        op.drop_index(f"ix_investigation_memory_records_{column}", table_name="investigation_memory_records")
    op.drop_table("investigation_memory_records")
