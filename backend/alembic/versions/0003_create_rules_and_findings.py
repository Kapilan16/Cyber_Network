"""Create rules and findings tables

Revision ID: 0003_create_rules_and_findings
Revises: 0002_create_raw_submissions
Create Date: 2026-09-27
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003_create_rules_and_findings"
down_revision = "0002_create_raw_submissions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Severity enum (shared by rules + findings) ────────────────────────
    severity_enum = sa.Enum("low", "medium", "high", "critical", name="severity")
    severity_enum.create(op.get_bind(), checkfirst=True)

    # ── rules table ───────────────────────────────────────────────────────
    op.create_table(
        "rules",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("condition_json", sa.JSON(), nullable=False),
        sa.Column(
            "severity",
            postgresql.ENUM("low", "medium", "high", "critical", name="severity", create_type=False),
            nullable=False,
            server_default="medium",
        ),
        sa.Column("mitre_technique_id", sa.String(20), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_rules_id", "rules", ["id"], unique=False)

    # ── findings table ────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "submission_id",
            sa.Integer(),
            sa.ForeignKey("raw_submissions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "rule_id",
            sa.Integer(),
            sa.ForeignKey("rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("matched_snippet", sa.String(500), nullable=True),
        sa.Column(
            "severity",
            postgresql.ENUM("low", "medium", "high", "critical", name="severity", create_type=False),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_findings_id",            "findings", ["id"],            unique=False)
    op.create_index("ix_findings_submission_id", "findings", ["submission_id"], unique=False)
    op.create_index("ix_findings_rule_id",       "findings", ["rule_id"],       unique=False)
    op.create_index("ix_findings_created_at",    "findings", ["created_at"],    unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_created_at",    table_name="findings")
    op.drop_index("ix_findings_rule_id",       table_name="findings")
    op.drop_index("ix_findings_submission_id", table_name="findings")
    op.drop_index("ix_findings_id",            table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_rules_id", table_name="rules")
    op.drop_table("rules")

    sa.Enum(name="severity").drop(op.get_bind(), checkfirst=True)
