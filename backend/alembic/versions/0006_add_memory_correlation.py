"""Add long-term memory nodes and correlation links.

Revision ID: 0006
Revises: 0005
"""
from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    sa.Enum(
        "mitre_technique",
        "rule",
        "embedding_cluster",
        name="memory_signature_type",
    ).create(bind, checkfirst=True)
    sa.Enum("active", "dormant", name="memory_node_status").create(
        bind, checkfirst=True
    )
    sa.Enum(
        "shared_technique",
        "shared_rule",
        "embedding_similarity",
        name="correlation_link_reason",
    ).create(bind, checkfirst=True)

    op.create_table(
        "memory_nodes",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "signature_type",
            postgresql.ENUM(
                "mitre_technique",
                "rule",
                "embedding_cluster",
                name="memory_signature_type",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("signature_key", sa.String(255), nullable=False),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("occurrence_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "active",
                "dormant",
                name="memory_node_status",
                create_type=False,
            ),
            server_default="active",
            nullable=False,
        ),
        sa.Column("summary", sa.Text(), nullable=True),
    )
    op.create_index("ix_memory_nodes_id", "memory_nodes", ["id"])
    op.create_index("ix_memory_nodes_signature_type", "memory_nodes", ["signature_type"])
    op.create_index("ix_memory_nodes_status", "memory_nodes", ["status"])

    op.create_table(
        "correlation_links",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "memory_node_id",
            sa.Integer(),
            sa.ForeignKey("memory_nodes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "submission_id",
            sa.Integer(),
            sa.ForeignKey("raw_submissions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "linked_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "link_reason",
            postgresql.ENUM(
                "shared_technique",
                "shared_rule",
                "embedding_similarity",
                name="correlation_link_reason",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("similarity_score", sa.Float(), nullable=True),
    )
    op.create_index("ix_correlation_links_id", "correlation_links", ["id"])
    op.create_index(
        "ix_correlation_links_memory_node_id",
        "correlation_links",
        ["memory_node_id"],
    )
    op.create_index(
        "ix_correlation_links_submission_id",
        "correlation_links",
        ["submission_id"],
    )
    op.create_index(
        "ix_correlation_links_finding_id",
        "correlation_links",
        ["finding_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_correlation_links_finding_id", table_name="correlation_links")
    op.drop_index("ix_correlation_links_submission_id", table_name="correlation_links")
    op.drop_index("ix_correlation_links_memory_node_id", table_name="correlation_links")
    op.drop_index("ix_correlation_links_id", table_name="correlation_links")
    op.drop_table("correlation_links")

    op.drop_index("ix_memory_nodes_status", table_name="memory_nodes")
    op.drop_index("ix_memory_nodes_signature_type", table_name="memory_nodes")
    op.drop_index("ix_memory_nodes_id", table_name="memory_nodes")
    op.drop_table("memory_nodes")

    sa.Enum(name="correlation_link_reason").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="memory_node_status").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="memory_signature_type").drop(op.get_bind(), checkfirst=True)
