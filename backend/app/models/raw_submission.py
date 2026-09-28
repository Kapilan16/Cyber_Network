"""
RawSubmission ORM model — stores analyst-submitted security artifacts
alongside their sanitized counterparts and semantic embeddings.
"""
import enum
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.types import JSON

from app.core.database import Base

# ── pgvector import with SQLite fallback ─────────────────────────────────────
# In production (Postgres + pgvector extension), Vector stores a real
# vector(1536) column.  In tests (SQLite), we fall back to Text so that
# Base.metadata.create_all succeeds without the extension.
try:
    from pgvector.sqlalchemy import Vector as _PgVector  # type: ignore[import]

    def _vector_column(dim: int):  # type: ignore[return]
        return Column(_PgVector(dim).with_variant(JSON(), "sqlite"), nullable=True)

except ImportError:  # pragma: no cover
    def _vector_column(dim: int):  # type: ignore[return]
        return Column(Text, nullable=True)


class SourceType(str, enum.Enum):
    alert = "alert"
    log = "log"
    report = "report"
    freeform = "freeform"


class SanitizationStatus(str, enum.Enum):
    pending = "pending"    # inserted but not yet processed (future async path)
    clean = "clean"        # processed; nothing suspicious found
    redacted = "redacted"  # processed; secrets / PII were redacted
    flagged = "flagged"    # processed; suspicious shell/script patterns detected


class EmbeddingStatus(str, enum.Enum):
    pending  = "pending"   # not yet embedded
    complete = "complete"  # embedding stored successfully
    failed   = "failed"    # embedding call failed (non-blocking)


class RawSubmission(Base):
    __tablename__ = "raw_submissions"

    id: int = Column(Integer, primary_key=True, index=True)
    user_id: int = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    raw_text: str = Column(Text, nullable=False)
    source_type: SourceType = Column(
        Enum(SourceType, name="sourcetype"),
        nullable=False,
        default=SourceType.freeform,
        server_default=SourceType.freeform.value,
    )
    submitted_at: datetime = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    sanitized_text: str = Column(Text, nullable=True)
    sanitization_status: SanitizationStatus = Column(
        Enum(SanitizationStatus, name="sanitizationstatus"),
        nullable=False,
        default=SanitizationStatus.pending,
        server_default=SanitizationStatus.pending.value,
    )

    # ── Embedding fields ──────────────────────────────────────────────────
    # embedding:        vector(1536) in Postgres, TEXT in SQLite test env
    # embedding_status: tracks async pipeline state
    embedding = _vector_column(1536)
    embedding_status: EmbeddingStatus = Column(
        Enum(EmbeddingStatus, name="embeddingstatus"),
        nullable=False,
        default=EmbeddingStatus.pending,
        server_default=EmbeddingStatus.pending.value,
    )

    # ── Relationships ─────────────────────────────────────────────────────
    submitter = relationship("User", back_populates="submissions", lazy="select")
    findings = relationship("Finding", back_populates="submission", lazy="dynamic")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<RawSubmission id={self.id} user_id={self.user_id} "
            f"status={self.sanitization_status} embed={self.embedding_status}>"
        )
