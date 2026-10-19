"""Create deterministic local submission risk scores.

Revision ID: 0014
Revises: 0013
"""
from alembic import op
import sqlalchemy as sa

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "risk_scores",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "submission_id",
            sa.Integer(),
            sa.ForeignKey("raw_submissions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column(
            "band",
            sa.Enum(
                "low",
                "medium",
                "high",
                "critical",
                name="riskband",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("components", sa.JSON(), nullable=False),
        sa.Column(
            "computed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "submission_id",
            name="uq_risk_scores_submission_id",
        ),
    )
    op.create_index("ix_risk_scores_id", "risk_scores", ["id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_risk_scores_id", table_name="risk_scores")
    op.drop_table("risk_scores")
