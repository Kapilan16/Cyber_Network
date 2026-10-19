"""Create cached submission AI recommendations.

Revision ID: 0015
Revises: 0014
"""
from alembic import op
import sqlalchemy as sa

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_recommendations",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "submission_id",
            sa.Integer(),
            sa.ForeignKey("raw_submissions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("recommendation_text", sa.Text(), nullable=True),
        sa.Column("suggested_actions", sa.JSON(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("model_used", sa.String(length=120), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "complete",
                "failed",
                name="recommendationstatus",
                native_enum=False,
                create_constraint=True,
            ),
            server_default="pending",
            nullable=False,
        ),
        sa.Column("error", sa.String(length=200), nullable=True),
        sa.UniqueConstraint(
            "submission_id",
            name="uq_ai_recommendations_submission_id",
        ),
    )
    op.create_index(
        "ix_ai_recommendations_id",
        "ai_recommendations",
        ["id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_ai_recommendations_id", table_name="ai_recommendations")
    op.drop_table("ai_recommendations")
