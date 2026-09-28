"""Create mitre_techniques table

Revision ID: 0004_create_mitre_techniques
Revises: 0003_create_rules_and_findings
Create Date: 2026-09-27
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_create_mitre_techniques"
down_revision = "0003_create_rules_and_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mitre_techniques",
        sa.Column("id",          sa.String(20),  primary_key=True, nullable=False),
        sa.Column("name",        sa.String(255), nullable=False),
        sa.Column("tactic",      sa.String(100), nullable=False),
        sa.Column("description", sa.Text(),      nullable=True),
    )
    op.create_index("ix_mitre_techniques_tactic", "mitre_techniques", ["tactic"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_mitre_techniques_tactic", table_name="mitre_techniques")
    op.drop_table("mitre_techniques")
