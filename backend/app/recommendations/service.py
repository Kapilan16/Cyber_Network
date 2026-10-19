"""Build bounded advisory context and generate persisted recommendations."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session, sessionmaker

from app.central_client import (
    CentralClient,
    CentralClientConfigurationError,
    CentralRequestError,
    CentralUnavailableError,
)
from app.core.config import settings
from app.core.database import SessionLocal
from app.models.enrichment import EnrichmentResult
from app.models.raw_submission import RawSubmission
from app.models.recommendation import AiRecommendation, RecommendationStatus
from app.models.risk_score import RiskScore
from app.models.rule import Finding, Rule
from app.recommendations.client import (
    RecommendationClient,
    RecommendationGenerationError,
)

logger = logging.getLogger(__name__)


def _embedding_values(value: object) -> list[float] | None:
    try:
        if isinstance(value, str):
            value = json.loads(value)
        if hasattr(value, "tolist"):
            value = value.tolist()
        return [float(component) for component in value]  # type: ignore[union-attr]
    except (TypeError, ValueError):
        return None


def build_recommendation_context(
    db: Session,
    submission: RawSubmission,
) -> dict:
    """Select only bounded, relevant local evidence and optional network context."""
    findings = (
        db.query(Finding, Rule)
        .join(Rule, Finding.rule_id == Rule.id)
        .filter(Finding.submission_id == submission.id)
        .order_by(Finding.id)
        .limit(50)
        .all()
    )
    risk = (
        db.query(RiskScore)
        .filter(RiskScore.submission_id == submission.id)
        .one_or_none()
    )
    enrichment = (
        db.query(EnrichmentResult)
        .filter(
            EnrichmentResult.submission_id == submission.id,
        )
        .order_by(EnrichmentResult.id)
        .limit(50)
        .all()
    )
    context = {
        "sanitized_submission_text": (submission.sanitized_text or "")[:12000],
        "matched_rules": [
            {
                "rule_name": rule.name,
                "severity": (
                    finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity)
                ),
                "mitre_technique_id": rule.mitre_technique_id,
                "matched_snippet": (finding.matched_snippet or "")[:300],
            }
            for finding, rule in findings
        ],
        "risk_score": (
            {"score": risk.score, "band": risk.band.value}
            if risk is not None
            else None
        ),
        "enrichment_results": [
            {
                "ioc_type": result.ioc_type.value,
                "ioc_value": result.ioc_value,
                "source": result.source.value,
                "reputation_score": result.reputation_score,
            }
            for result in enrichment
        ],
        "similar_network_incidents": [],
    }

    embedding = _embedding_values(submission.embedding)
    if embedding is None or not settings.CENTRAL_SERVER_URL or not settings.CENTRAL_API_KEY:
        return context
    try:
        with CentralClient() as central:
            response = central.search_intel(embedding, top_k=3)
        context["similar_network_incidents"] = [
            {
                "sanitized_text": str(item.get("sanitized_text", ""))[:300],
                "similarity_score": round(float(item.get("similarity_score", 0)), 3),
            }
            for item in response.get("results", [])[:3]
        ]
    except (
        CentralClientConfigurationError,
        CentralRequestError,
        CentralUnavailableError,
        KeyError,
        TypeError,
        ValueError,
    ):
        logger.info(
            "Central network context unavailable for recommendation on submission %s",
            submission.id,
        )
    return context


def generate_recommendation_background(
    recommendation_id: int,
    *,
    session_factory: Callable[[], Session] = SessionLocal,
    client: RecommendationClient | None = None,
) -> None:
    db = session_factory()
    try:
        recommendation = db.get(AiRecommendation, recommendation_id)
        if recommendation is None or recommendation.status != RecommendationStatus.pending:
            return
        submission = db.get(RawSubmission, recommendation.submission_id)
        if submission is None:
            _mark_failed(recommendation, "Submission is no longer available")
            db.commit()
            return
        if not submission.sanitized_text:
            _mark_failed(recommendation, "Submission has no sanitized text")
            db.commit()
            return

        context = build_recommendation_context(db, submission)
        generated = (client or RecommendationClient()).generate(context)
        recommendation.recommendation_text = generated.recommendation_text
        recommendation.suggested_actions = generated.suggested_actions
        recommendation.confidence = generated.confidence
        recommendation.generated_at = datetime.now(timezone.utc)
        recommendation.model_used = settings.AI_MODEL
        recommendation.status = RecommendationStatus.complete
        recommendation.error = None
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.exception(
            "Recommendation generation failed for recommendation %s",
            recommendation_id,
        )
        recommendation = db.get(AiRecommendation, recommendation_id)
        if recommendation is not None:
            _mark_failed(recommendation, _safe_error(exc))
            db.commit()
    finally:
        db.close()


def _mark_failed(recommendation: AiRecommendation, message: str) -> None:
    recommendation.status = RecommendationStatus.failed
    recommendation.error = message[:200]
    recommendation.generated_at = datetime.now(timezone.utc)


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, RecommendationGenerationError):
        return str(exc)
    return "Recommendation generation failed"
