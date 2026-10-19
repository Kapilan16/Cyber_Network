"""Add recurrence fields to memory nodes.

Revision ID: 0008
Revises: 0007
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "memory_nodes",
        sa.Column(
            "is_recurring",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "memory_nodes",
        sa.Column(
            "recurrence_window_days",
            sa.Integer(),
            nullable=False,
            server_default="30",
        ),
    )
    op.add_column(
        "memory_nodes",
        sa.Column(
            "recurrence_threshold",
            sa.Integer(),
            nullable=False,
            server_default="3",
        ),
    )
    op.create_index("ix_memory_nodes_is_recurring", "memory_nodes", ["is_recurring"])


def downgrade() -> None:
    op.drop_index("ix_memory_nodes_is_recurring", table_name="memory_nodes")
    op.drop_column("memory_nodes", "recurrence_threshold")
    op.drop_column("memory_nodes", "recurrence_window_days")
    op.drop_column("memory_nodes", "is_recurring")
