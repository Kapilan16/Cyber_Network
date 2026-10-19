"""Create local-only IOC enrichment result storage.

Revision ID: 0013
Revises: 0012
"""
from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enrichment_results",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "submission_id",
            sa.Integer(),
            sa.ForeignKey("raw_submissions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ioc_type",
            sa.Enum(
                "ip",
                "domain",
                "hash",
                name="ioctype",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("ioc_value", sa.String(length=255), nullable=False),
        sa.Column(
            "source",
            sa.Enum(
                "virustotal",
                "abuseipdb",
                name="enrichmentsource",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("reputation_score", sa.Integer(), nullable=True),
        sa.Column("raw_response_summary", sa.JSON(), nullable=True),
        sa.Column("queried_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "complete",
                "failed",
                name="enrichmentstatus",
                native_enum=False,
                create_constraint=True,
            ),
            server_default="pending",
            nullable=False,
        ),
        sa.UniqueConstraint(
            "submission_id",
            "ioc_type",
            "ioc_value",
            "source",
            name="uq_enrichment_submission_ioc_source",
        ),
    )
    op.create_index(
        "ix_enrichment_results_id",
        "enrichment_results",
        ["id"],
        unique=False,
    )
    op.create_index(
        "ix_enrichment_submission_id",
        "enrichment_results",
        ["submission_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_enrichment_submission_id", table_name="enrichment_results")
    op.drop_index("ix_enrichment_results_id", table_name="enrichment_results")
    op.drop_table("enrichment_results")
