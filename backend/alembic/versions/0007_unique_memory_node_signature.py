"""Make memory-node signatures unique.

Revision ID: 0007
Revises: 0006
"""
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_memory_nodes_signature",
        "memory_nodes",
        ["signature_type", "signature_key"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_memory_nodes_signature",
        "memory_nodes",
        type_="unique",
    )
