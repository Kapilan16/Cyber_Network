"""Persistence and optional local/central recurrence calculation."""
from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.central_client import (
    CentralClient,
    CentralClientConfigurationError,
    CentralRequestError,
    CentralUnavailableError,
)
from app.core.config import settings
from app.core.database import SessionLocal
from app.models.enrichment import EnrichmentResult, EnrichmentStatus
from app.models.raw_submission import RawSubmission
from app.models.risk_score import RiskScore
from app.models.rule import Finding
from app.risk.scoring import calculate_risk_score
from app.search.faiss_index import get_faiss_index

logger = logging.getLogger(__name__)


def _vector_values(vector: object) -> list[float] | None:
    try:
        if isinstance(vector, str):
            vector = json.loads(vector)
        if hasattr(vector, "tolist"):
            vector = vector.tolist()
        values = [float(value) for value in vector]  # type: ignore[union-attr]
        if not values or any(not math.isfinite(value) for value in values):
            return None
        return values
    except (TypeError, ValueError):
        return None


def _cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        return 0.0
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if not left_norm or not right_norm:
        return 0.0
    return sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)


def count_local_recurrences(
    db: Session,
    submission: RawSubmission,
    *,
    threshold: float,
    max_matches: int,
) -> int:
    """Count prior local submissions among the nearest indexed/database vectors."""
    query_vector = _vector_values(submission.embedding)
    if query_vector is None or submission.id is None:
        return 0

    index = get_faiss_index()
    candidate_ids: list[int] = []
    if index.available and index.count:
        candidates = index.search(query_vector, min(index.count, 500))
        if candidates is not None:
            candidate_ids = [item_id for item_id, _score in candidates]

    candidates_query = db.query(RawSubmission).filter(
        RawSubmission.id != submission.id,
        RawSubmission.embedding.is_not(None),
        RawSubmission.submitted_at >= (
            datetime.now(timezone.utc)
            - timedelta(days=settings.CORRELATION_WINDOW_DAYS)
        ),
        or_(
            RawSubmission.submitted_at < submission.submitted_at,
            (
                (RawSubmission.submitted_at == submission.submitted_at)
                & (RawSubmission.id < submission.id)
            ),
        ),
    )
    if candidate_ids:
        candidates_query = candidates_query.filter(
            RawSubmission.id.in_(candidate_ids)
        )
    matches = 0
    for previous in candidates_query.all():
        previous_vector = _vector_values(previous.embedding)
        if previous_vector is not None and _cosine(query_vector, previous_vector) >= threshold:
            matches += 1
            if matches >= max_matches:
                return matches
    return matches


def count_network_recurrences(
    embedding: list[float] | None,
    *,
    threshold: float,
) -> int:
    """Return central cross-org similar-hit count; failures safely mean local-only."""
    if embedding is None or not settings.CENTRAL_SERVER_URL or not settings.CENTRAL_API_KEY:
        return 0
    try:
        with CentralClient() as central:
            response = central.search_intel(embedding, top_k=10)
        return sum(
            1
            for result in response.get("results", [])
            if float(result.get("similarity_score", 0)) >= threshold
        )
    except (
        CentralClientConfigurationError,
        CentralRequestError,
        CentralUnavailableError,
        KeyError,
        TypeError,
        ValueError,
    ):
        logger.warning(
            "Central recurrence lookup unavailable; scoring with local matches only",
            exc_info=True,
        )
        return 0


def compute_submission_risk_score(
    db: Session,
    submission_id: int,
    *,
    include_network: bool = True,
) -> RiskScore | None:
    """Upsert a score; defer while any enrichment lookup remains pending."""
    submission = (
        db.query(RawSubmission)
        .filter(RawSubmission.id == submission_id)
        .first()
    )
    if submission is None:
        return None
    pending_enrichment = (
        db.query(EnrichmentResult.id)
        .filter(
            EnrichmentResult.submission_id == submission_id,
            EnrichmentResult.status == EnrichmentStatus.pending,
        )
        .first()
    )
    if pending_enrichment is not None:
        return None

    severities = [
        finding.severity.value
        if hasattr(finding.severity, "value")
        else str(finding.severity)
        for finding in db.query(Finding)
        .filter(Finding.submission_id == submission_id)
        .all()
    ]
    local_count = count_local_recurrences(
        db,
        submission,
        threshold=settings.RISK_RECURRENCE_SIMILARITY_THRESHOLD,
        max_matches=settings.RISK_RECURRENCE_MAX_MATCHES,
    )
    embedding = _vector_values(submission.embedding)
    network_count = (
        count_network_recurrences(
            embedding,
            threshold=settings.RISK_RECURRENCE_SIMILARITY_THRESHOLD,
        )
        if include_network
        else 0
    )
    reputation_values = [
        result.reputation_score
        for result in db.query(EnrichmentResult)
        .filter(
            EnrichmentResult.submission_id == submission_id,
            EnrichmentResult.status == EnrichmentStatus.complete,
            EnrichmentResult.reputation_score.is_not(None),
        )
        .all()
        if result.reputation_score is not None
    ]
    calculation = calculate_risk_score(
        severities,
        local_count,
        max(reputation_values, default=None),
        network_recurrence_count=network_count,
        weights={
            "rule_severity": settings.RISK_WEIGHT_RULE_SEVERITY,
            "recurrence": settings.RISK_WEIGHT_RECURRENCE,
            "enrichment": settings.RISK_WEIGHT_ENRICHMENT,
        },
        max_recurrence_matches=settings.RISK_RECURRENCE_MAX_MATCHES,
        network_recurrence_multiplier=settings.RISK_NETWORK_RECURRENCE_MULTIPLIER,
    )

    risk = (
        db.query(RiskScore)
        .filter(RiskScore.submission_id == submission_id)
        .one_or_none()
    )
    if risk is None:
        risk = RiskScore(submission_id=submission_id)
        db.add(risk)
    risk.score = calculation.score
    risk.band = calculation.band
    risk.components = calculation.components
    risk.computed_at = datetime.now(timezone.utc)
    return risk


def compute_submission_risk_score_background(
    submission_id: int,
    *,
    session_factory: Callable[[], Session] = SessionLocal,
) -> None:
    db = session_factory()
    try:
        compute_submission_risk_score(db, submission_id)
        db.commit()
        try:
            from app.analytics.warnings import scan_early_warnings

            scan_early_warnings(db)
        except Exception:
            logger.exception(
                "Risk score persisted, but early-warning scan failed for submission %s",
                submission_id,
            )
    except Exception:
        db.rollback()
        logger.exception("Could not compute risk score for submission %s", submission_id)
    finally:
        db.close()
