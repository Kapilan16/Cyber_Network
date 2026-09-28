"""Create raw_submissions table

Revision ID: 0002_create_raw_submissions
Revises: 0001_create_users
Create Date: 2026-09-27

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "0002_create_raw_submissions"
down_revision = "0001_create_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Enum types ────────────────────────────────────────────────────────
    sourcetype_enum = sa.Enum(
        "alert", "log", "report", "freeform", name="sourcetype"
    )
    sourcetype_enum.create(op.get_bind(), checkfirst=True)

    sanitizationstatus_enum = sa.Enum(
        "pending", "clean", "redacted", "flagged", name="sanitizationstatus"
    )
    sanitizationstatus_enum.create(op.get_bind(), checkfirst=True)

    # ── Table ─────────────────────────────────────────────────────────────
    op.create_table(
        "raw_submissions",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("raw_text", sa.Text(), nullable=False),
        sa.Column(
            "source_type",
            postgresql.ENUM("alert", "log", "report", "freeform", name="sourcetype", create_type=False),
            nullable=False,
            server_default="freeform",
        ),
        sa.Column(
            "submitted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("sanitized_text", sa.Text(), nullable=True),
        sa.Column(
            "sanitization_status",
            postgresql.ENUM(
                "pending", "clean", "redacted", "flagged",
                name="sanitizationstatus", create_type=False,
            ),
            nullable=False,
            server_default="pending",
        ),
    )
    op.create_index("ix_raw_submissions_id", "raw_submissions", ["id"], unique=False)
    op.create_index(
        "ix_raw_submissions_user_id", "raw_submissions", ["user_id"], unique=False
    )
    op.create_index(
        "ix_raw_submissions_submitted_at",
        "raw_submissions",
        ["submitted_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_raw_submissions_submitted_at", table_name="raw_submissions")
    op.drop_index("ix_raw_submissions_user_id", table_name="raw_submissions")
    op.drop_index("ix_raw_submissions_id", table_name="raw_submissions")
    op.drop_table("raw_submissions")
    sa.Enum(name="sanitizationstatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="sourcetype").drop(op.get_bind(), checkfirst=True)
