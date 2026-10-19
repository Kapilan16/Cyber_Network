"""Persistent local threat-intelligence lookup results."""
import enum
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.sql import func

from app.core.database import Base


class IOCType(str, enum.Enum):
    ip = "ip"
    domain = "domain"
    hash = "hash"


class EnrichmentSource(str, enum.Enum):
    virustotal = "virustotal"
    abuseipdb = "abuseipdb"


class EnrichmentStatus(str, enum.Enum):
    pending = "pending"
    complete = "complete"
    failed = "failed"


class EnrichmentResult(Base):
    __tablename__ = "enrichment_results"
    __table_args__ = (
        UniqueConstraint(
            "submission_id",
            "ioc_type",
            "ioc_value",
            "source",
            name="uq_enrichment_submission_ioc_source",
        ),
        Index("ix_enrichment_submission_id", "submission_id"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    submission_id: int = Column(
        Integer,
        ForeignKey("raw_submissions.id", ondelete="CASCADE"),
        nullable=False,
    )
    ioc_type: IOCType = Column(
        Enum(IOCType, name="ioctype", native_enum=False, create_constraint=True),
        nullable=False,
    )
    ioc_value: str = Column(String(255), nullable=False)
    source: EnrichmentSource = Column(
        Enum(
            EnrichmentSource,
            name="enrichmentsource",
            native_enum=False,
            create_constraint=True,
        ),
        nullable=False,
    )
    reputation_score: int | None = Column(Integer, nullable=True)
    raw_response_summary: dict | None = Column(JSON, nullable=True)
    queried_at: datetime | None = Column(DateTime(timezone=True), nullable=True)
    status: EnrichmentStatus = Column(
        Enum(
            EnrichmentStatus,
            name="enrichmentstatus",
            native_enum=False,
            create_constraint=True,
        ),
        nullable=False,
        default=EnrichmentStatus.pending,
        server_default=EnrichmentStatus.pending.value,
    )
