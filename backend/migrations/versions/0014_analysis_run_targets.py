"""Bind AI analysis runs to an optional project target."""
from alembic import op
import sqlalchemy as sa

revision = "0014_analysis_run_targets"
down_revision = "0013_ai_analysis_evaluations"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("ai_analysis_runs") as batch:
        batch.add_column(sa.Column("target_id", sa.Integer(), nullable=True))
        batch.create_foreign_key(
            "fk_ai_analysis_runs_target_id_targets", "targets", ["target_id"], ["id"]
        )
    op.create_index("ix_ai_analysis_runs_target_id", "ai_analysis_runs", ["target_id"])


def downgrade():
    op.drop_index("ix_ai_analysis_runs_target_id", table_name="ai_analysis_runs")
    with op.batch_alter_table("ai_analysis_runs") as batch:
        batch.drop_constraint("fk_ai_analysis_runs_target_id_targets", type_="foreignkey")
        batch.drop_column("target_id")
