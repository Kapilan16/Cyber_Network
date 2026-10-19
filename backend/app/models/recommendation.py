"""Cached LLM-generated analyst recommendations."""
import enum
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)

from app.core.database import Base


class RecommendationStatus(str, enum.Enum):
    pending = "pending"
    complete = "complete"
    failed = "failed"


class AiRecommendation(Base):
    __tablename__ = "ai_recommendations"
    __table_args__ = (
        UniqueConstraint(
            "submission_id",
            name="uq_ai_recommendations_submission_id",
        ),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    submission_id: int = Column(
        Integer,
        ForeignKey("raw_submissions.id", ondelete="CASCADE"),
        nullable=False,
    )
    recommendation_text: str | None = Column(Text, nullable=True)
    suggested_actions: list[str] | None = Column(JSON, nullable=True)
    confidence: float | None = Column(Float(), nullable=True)
    generated_at: datetime | None = Column(DateTime(timezone=True), nullable=True)
    model_used: str | None = Column(String(120), nullable=True)
    status: RecommendationStatus = Column(
        Enum(
            RecommendationStatus,
            name="recommendationstatus",
            native_enum=False,
            create_constraint=True,
        ),
        nullable=False,
        default=RecommendationStatus.pending,
        server_default=RecommendationStatus.pending.value,
    )
    error: str | None = Column(String(200), nullable=True)
