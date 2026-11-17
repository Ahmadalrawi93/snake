"""Link investigation memory to immutable human-reviewed candidates."""
from alembic import op
import sqlalchemy as sa

revision = "0021_investigation_memory_candidate_link"
down_revision = "0020_investigation_memory"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("investigation_memory_records", sa.Column("candidate_fingerprint", sa.String(64), nullable=True))
    op.create_index("ix_investigation_memory_records_candidate_fingerprint", "investigation_memory_records", ["candidate_fingerprint"])

def downgrade():
    op.drop_index("ix_investigation_memory_records_candidate_fingerprint", table_name="investigation_memory_records")
    op.drop_column("investigation_memory_records", "candidate_fingerprint")
