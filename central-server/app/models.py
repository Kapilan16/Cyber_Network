"""Central registry models."""
import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.sql import func

from app.database import Base
from app.config import settings

try:
    from pgvector.sqlalchemy import Vector

    def _embedding_column():
        return Column(
            Vector(settings.CENTRAL_VECTOR_DIM).with_variant(JSON(), "sqlite"),
            nullable=True,
        )
except ImportError:  # pragma: no cover - central requirements install pgvector
    def _embedding_column():
        return Column(JSON, nullable=True)


class OrganizationStatus(str, enum.Enum):
    active = "active"
    suspended = "suspended"


class Organization(Base):
    __tablename__ = "organizations"

    id: int = Column(Integer, primary_key=True, index=True)
    name: str = Column(String(255), nullable=False)
    api_key_hash: str = Column(String(64), nullable=False, unique=True)
    registered_at: datetime = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    status: OrganizationStatus = Column(
        Enum(
            OrganizationStatus,
            name="organizationstatus",
            native_enum=False,
            create_constraint=True,
        ),
        nullable=False,
        default=OrganizationStatus.active,
        server_default=OrganizationStatus.active.value,
    )
    contact_email: str | None = Column(String(320), nullable=True)


class SharedIntel(Base):
    __tablename__ = "shared_intel"
    __table_args__ = (
        UniqueConstraint(
            "source_org_id",
            "dedup_hash",
            name="uq_shared_intel_source_dedup",
        ),
        Index("ix_shared_intel_received_at", "received_at"),
        Index("ix_shared_intel_source_org_id", "source_org_id"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    source_org_id: int = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    mitre_technique_ids: list[str] = Column(JSON, nullable=False, default=list)
    severity: list[str] = Column(JSON, nullable=False, default=list)
    # Preserve the category-only field produced by the org-local payload builder.
    rule_categories: list[str] = Column(JSON, nullable=False, default=list)
    sanitized_text: str = Column(Text, nullable=False)
    embedding = _embedding_column()
    dedup_hash: str = Column(String(64), nullable=False)
    received_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
