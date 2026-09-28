"""0005 — add pgvector extension and embedding columns to raw_submissions.

Revision: 0005
Previous: 0004_create_mitre_techniques
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic
revision = "0005"
down_revision = "0004_create_mitre_techniques"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    # ── 1. Enable pgvector extension ──────────────────────────────────────
    # CREATE EXTENSION IF NOT EXISTS is idempotent and safe to re-run.
    conn.execute(sa.text("CREATE EXTENSION IF NOT EXISTS vector"))

    # ── 2. Add embedding_status enum type ────────────────────────────────
    # Use raw DDL so we don't need alembic to manage the PG enum lifecycle.
    conn.execute(sa.text(
        "DO $$ BEGIN "
        "  CREATE TYPE embeddingstatus AS ENUM ('pending', 'complete', 'failed'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; "
        "END $$"
    ))

    # ── 3. Add columns to raw_submissions ─────────────────────────────────
    op.add_column(
        "raw_submissions",
        sa.Column(
            "embedding_status",
            sa.Enum("pending", "complete", "failed", name="embeddingstatus", create_type=False),
            nullable=False,
            server_default="pending",
        ),
    )
    # vector(1536) — raw DDL because SQLAlchemy core doesn't know the type.
    conn.execute(sa.text(
        "ALTER TABLE raw_submissions ADD COLUMN IF NOT EXISTS embedding vector(1536)"
    ))

    # ── 4. HNSW index for fast approximate nearest-neighbour search ────────
    # vector_cosine_ops matches the <=> (cosine distance) operator we use.
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_raw_submissions_embedding "
        "ON raw_submissions "
        "USING hnsw (embedding vector_cosine_ops)"
    ))


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text("DROP INDEX IF EXISTS ix_raw_submissions_embedding"))
    conn.execute(sa.text("ALTER TABLE raw_submissions DROP COLUMN IF EXISTS embedding"))
    op.drop_column("raw_submissions", "embedding_status")
    conn.execute(sa.text("DROP TYPE IF EXISTS embeddingstatus"))
    # Note: we intentionally do NOT drop the vector extension on downgrade
    # because other tables/columns might depend on it.
