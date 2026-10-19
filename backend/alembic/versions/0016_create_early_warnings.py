"""Create rule-based early warning records.

Revision ID: 0016
Revises: 0015
"""
from alembic import op
import sqlalchemy as sa

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "early_warnings",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "org_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("warning_key", sa.String(length=160), nullable=False),
        sa.Column(
            "triggered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("submission_ids", sa.JSON(), nullable=False),
        sa.UniqueConstraint("warning_key", name="uq_early_warnings_warning_key"),
    )
    op.create_index(
        "ix_early_warnings_id",
        "early_warnings",
        ["id"],
        unique=False,
    )
    op.create_index(
        "ix_early_warnings_org_triggered",
        "early_warnings",
        ["org_id", "triggered_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_early_warnings_org_triggered", table_name="early_warnings")
    op.drop_index("ix_early_warnings_id", table_name="early_warnings")
    op.drop_table("early_warnings")
