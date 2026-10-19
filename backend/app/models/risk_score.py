"""Persisted deterministic composite risk scores."""
import enum
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.sql import func

from app.core.database import Base


class RiskBand(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RiskScore(Base):
    __tablename__ = "risk_scores"
    __table_args__ = (
        UniqueConstraint("submission_id", name="uq_risk_scores_submission_id"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    submission_id: int = Column(
        Integer,
        ForeignKey("raw_submissions.id", ondelete="CASCADE"),
        nullable=False,
    )
    score: int = Column(Integer, nullable=False)
    band: RiskBand = Column(
        Enum(RiskBand, name="riskband", native_enum=False, create_constraint=True),
        nullable=False,
    )
    components: dict = Column(JSON, nullable=False)
    computed_at: datetime = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
