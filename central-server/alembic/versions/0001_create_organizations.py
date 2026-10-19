"""Create central organization registry.

Revision ID: 0001
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("api_key_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "registered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "active",
                "suspended",
                name="organizationstatus",
                native_enum=False,
                create_constraint=True,
            ),
            server_default="active",
            nullable=False,
        ),
        sa.Column("contact_email", sa.String(length=320), nullable=True),
        sa.UniqueConstraint("api_key_hash", name="uq_organizations_api_key_hash"),
    )
    op.create_index("ix_organizations_id", "organizations", ["id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_organizations_id", table_name="organizations")
    op.drop_table("organizations")
