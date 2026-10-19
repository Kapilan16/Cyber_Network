"""Create the central anonymized intelligence store.

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

from app.config import settings

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.create_table(
        "shared_intel",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "source_org_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("mitre_technique_ids", sa.JSON(), nullable=False),
        sa.Column("severity", sa.JSON(), nullable=False),
        sa.Column("rule_categories", sa.JSON(), nullable=False),
        sa.Column("sanitized_text", sa.Text(), nullable=False),
        sa.Column("embedding", Vector(settings.CENTRAL_VECTOR_DIM), nullable=True),
        sa.Column("dedup_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "source_org_id",
            "dedup_hash",
            name="uq_shared_intel_source_dedup",
        ),
    )
    op.create_index("ix_shared_intel_id", "shared_intel", ["id"], unique=False)
    op.create_index(
        "ix_shared_intel_source_org_id",
        "shared_intel",
        ["source_org_id"],
        unique=False,
    )
    op.create_index(
        "ix_shared_intel_received_at",
        "shared_intel",
        ["received_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_shared_intel_received_at", table_name="shared_intel")
    op.drop_index("ix_shared_intel_source_org_id", table_name="shared_intel")
    op.drop_index("ix_shared_intel_id", table_name="shared_intel")
    op.drop_table("shared_intel")
