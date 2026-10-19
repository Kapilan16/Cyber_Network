"""Track organization network-sharing delivery status per submission.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "raw_submissions",
        sa.Column(
            "network_sync_status",
            sa.Enum(
                "not_shared",
                "pending",
                "shared",
                "duplicate",
                "failed",
                name="networksyncstatus",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
            server_default="not_shared",
        ),
    )
    op.add_column(
        "raw_submissions",
        sa.Column("network_sync_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "raw_submissions",
        sa.Column("network_synced_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_raw_submissions_network_sync_status",
        "raw_submissions",
        ["network_sync_status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_raw_submissions_network_sync_status",
        table_name="raw_submissions",
    )
    op.drop_column("raw_submissions", "network_synced_at")
    op.drop_column("raw_submissions", "network_sync_error")
    op.drop_column("raw_submissions", "network_sync_status")
