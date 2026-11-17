"""Bind AI analysis runs to an optional project target."""
from alembic import op
import sqlalchemy as sa

revision = "0014_analysis_run_targets"
down_revision = "0013_ai_analysis_evaluations"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ai_analysis_runs", sa.Column("target_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_ai_analysis_runs_target_id_targets",
        "ai_analysis_runs", "targets", ["target_id"], ["id"],
    )
    op.create_index("ix_ai_analysis_runs_target_id", "ai_analysis_runs", ["target_id"])


def downgrade():
    op.drop_index("ix_ai_analysis_runs_target_id", table_name="ai_analysis_runs")
    op.drop_constraint("fk_ai_analysis_runs_target_id_targets", "ai_analysis_runs", type_="foreignkey")
    op.drop_column("ai_analysis_runs", "target_id")
