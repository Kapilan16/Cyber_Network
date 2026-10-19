"""Add semantic embeddings for rule descriptions.

Revision ID: 0012
Revises: 0011
"""
from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("rules", sa.Column("description_embedding", Vector(1536), nullable=True))


def downgrade() -> None:
    op.drop_column("rules", "description_embedding")
