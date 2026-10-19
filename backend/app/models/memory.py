"""Long-term pattern memory and submission correlation ORM models."""
from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Column,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class SignatureType(str, enum.Enum):
    mitre_technique = "mitre_technique"
    rule = "rule"
    embedding_cluster = "embedding_cluster"


class MemoryNodeStatus(str, enum.Enum):
    active = "active"
    dormant = "dormant"


class LinkReason(str, enum.Enum):
    shared_technique = "shared_technique"
    shared_rule = "shared_rule"
    embedding_similarity = "embedding_similarity"


class MemoryNode(Base):
    __tablename__ = "memory_nodes"
    __table_args__ = (
        UniqueConstraint(
            "signature_type",
            "signature_key",
            name="uq_memory_nodes_signature",
        ),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    signature_type: SignatureType = Column(
        Enum(SignatureType, name="memory_signature_type"),
        nullable=False,
        index=True,
    )
    signature_key: str = Column(String(255), nullable=False)
    first_seen: datetime = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen: datetime = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    occurrence_count: int = Column(Integer, nullable=False, default=1, server_default="1")
    status: MemoryNodeStatus = Column(
        Enum(MemoryNodeStatus, name="memory_node_status"),
        nullable=False,
        default=MemoryNodeStatus.active,
        server_default=MemoryNodeStatus.active.value,
        index=True,
    )
    is_recurring: bool = Column(
        Boolean, nullable=False, default=False, server_default="false", index=True
    )
    recurrence_window_days: int = Column(
        Integer, nullable=False, default=30, server_default="30"
    )
    recurrence_threshold: int = Column(
        Integer, nullable=False, default=3, server_default="3"
    )
    summary: str | None = Column(Text, nullable=True)

    links = relationship("CorrelationLink", back_populates="memory_node", lazy="select")


class CorrelationLink(Base):
    __tablename__ = "correlation_links"

    id: int = Column(Integer, primary_key=True, index=True)
    memory_node_id: int = Column(
        Integer,
        ForeignKey("memory_nodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    submission_id: int = Column(
        Integer,
        ForeignKey("raw_submissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id: int | None = Column(
        Integer,
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    linked_at: datetime = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    link_reason: LinkReason = Column(
        Enum(LinkReason, name="correlation_link_reason"), nullable=False
    )
    similarity_score: float | None = Column(Float, nullable=True)

    memory_node = relationship("MemoryNode", back_populates="links", lazy="select")
    submission = relationship("RawSubmission", lazy="select")
    finding = relationship("Finding", lazy="select")
