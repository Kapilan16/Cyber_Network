"""Add local organizations and associate existing users.

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("api_key_hash", sa.String(length=64), nullable=True),
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
    )
    op.create_index("ix_organizations_id", "organizations", ["id"], unique=False)

    op.execute(
        sa.text(
            "INSERT INTO organizations (name, status) "
            "VALUES ('Default Organization', 'active')"
        )
    )
    organization_id = 1

    op.add_column(
        "users",
        sa.Column(
            "org_id",
            sa.Integer(),
            nullable=True,
            server_default=str(organization_id),
        ),
    )
    op.execute(
        sa.text("UPDATE users SET org_id = :organization_id").bindparams(
            organization_id=organization_id
        )
    )
    op.alter_column("users", "org_id", nullable=False)
    op.create_foreign_key(
        "fk_users_org_id_organizations",
        "users",
        "organizations",
        ["org_id"],
        ["id"],
    )
    op.create_index("ix_users_org_id", "users", ["org_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_users_org_id", table_name="users")
    op.drop_constraint("fk_users_org_id_organizations", "users", type_="foreignkey")
    op.drop_column("users", "org_id")
    op.drop_index("ix_organizations_id", table_name="organizations")
    op.drop_table("organizations")
