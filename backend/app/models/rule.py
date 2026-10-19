"""
Rule and Finding ORM models for the declarative rule engine.
"""
from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.types import JSON

from app.core.database import Base

try:
    from pgvector.sqlalchemy import Vector as _PgVector

    def _vector_column(dim: int):
        return Column(_PgVector(dim).with_variant(JSON(), "sqlite"), nullable=True)

except ImportError:  # pragma: no cover
    def _vector_column(dim: int):
        return Column(Text, nullable=True)


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Rule(Base):
    __tablename__ = "rules"

    id: int = Column(Integer, primary_key=True, index=True)
    name: str = Column(String(255), nullable=False, unique=True)
    description: str = Column(Text, nullable=True)
    condition_json: dict = Column(JSON, nullable=False)
    description_embedding = _vector_column(1536)
    severity: Severity = Column(
        Enum(Severity, name="severity"),
        nullable=False,
        default=Severity.medium,
        server_default=Severity.medium.value,
    )
    mitre_technique_id: str | None = Column(String(20), nullable=True)  # e.g. "T1059.001"
    is_active: bool = Column(Boolean, nullable=False, default=True, server_default="true")
    created_at: datetime = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ── Relationships ─────────────────────────────────────────────────────
    findings = relationship("Finding", back_populates="rule", lazy="dynamic")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Rule id={self.id} name={self.name!r} severity={self.severity}>"


class Finding(Base):
    __tablename__ = "findings"

    id: int = Column(Integer, primary_key=True, index=True)
    submission_id: int = Column(
        Integer,
        ForeignKey("raw_submissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id: int = Column(
        Integer,
        ForeignKey("rules.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    matched_snippet: str = Column(String(500), nullable=True)  # up to 500 chars of context
    severity: Severity = Column(
        Enum(Severity, name="severity"),
        nullable=False,
    )
    created_at: datetime = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    # ── Relationships ─────────────────────────────────────────────────────
    rule = relationship("Rule", back_populates="findings", lazy="select")
    submission = relationship("RawSubmission", back_populates="findings", lazy="select")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Finding id={self.id} submission_id={self.submission_id} "
            f"rule_id={self.rule_id} severity={self.severity}>"
        )
