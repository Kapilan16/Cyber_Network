"""Persisted rule-based early-warning events."""
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.sql import func

from app.core.database import Base


class EarlyWarning(Base):
    __tablename__ = "early_warnings"
    __table_args__ = (
        Index("ix_early_warnings_org_triggered", "org_id", "triggered_at"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    org_id: int = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    warning_key: str = Column(String(160), nullable=False, unique=True)
    triggered_at: datetime = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    description: str = Column(Text, nullable=False)
    submission_ids: list[int] = Column(JSON, nullable=False)
