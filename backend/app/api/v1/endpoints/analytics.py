"""Authenticated org-local analytics and active early warnings."""
from __future__ import annotations

import logging
from datetime import datetime, time, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.central_client import (
    CentralClient,
    CentralClientConfigurationError,
    CentralRequestError,
    CentralUnavailableError,
)
from app.core.config import settings
from app.core.database import get_db
from app.models.early_warning import EarlyWarning
from app.models.enrichment import EnrichmentResult, EnrichmentStatus
from app.models.mitre_technique import MitreTechnique
from app.models.organization import Organization
from app.models.raw_submission import RawSubmission
from app.models.risk_score import RiskBand, RiskScore
from app.models.rule import Finding, Rule
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter()


class CountItem(BaseModel):
    name: str
    count: int


class RiskTrendItem(BaseModel):
    date: str
    average_score: float
    submissions: int


class ActiveWarningOut(BaseModel):
    id: int
    triggered_at: str
    description: str
    submission_ids: list[int]


class NetworkTacticComparison(BaseModel):
    tactic: str
    local_count: int
    network_count: int


class NetworkContextOut(BaseModel):
    enabled: bool
    available: bool
    central_total: Optional[int] = None
    by_tactic: list[NetworkTacticComparison] = Field(default_factory=list)
    error: Optional[str] = None


class AnalyticsOverview(BaseModel):
    risk_band_distribution: list[CountItem]
    top_mitre_tactics: dict[str, list[CountItem]]
    enrichment_hit_rate: float
    enriched_iocs: int
    non_clean_iocs: int
    average_risk_score_trend: list[RiskTrendItem]
    network_context: Optional[NetworkContextOut]
    active_warnings: list[ActiveWarningOut]


def _tactic_counts(
    db: Session,
    org_id: int,
    *,
    since: datetime | None,
) -> dict[str, int]:
    query = (
        db.query(RawSubmission.id, MitreTechnique.tactic)
        .join(User, User.id == RawSubmission.user_id)
        .join(Finding, Finding.submission_id == RawSubmission.id)
        .join(Rule, Rule.id == Finding.rule_id)
        .join(MitreTechnique, MitreTechnique.id == Rule.mitre_technique_id)
        .filter(User.org_id == org_id)
    )
    if since is not None:
        query = query.filter(RawSubmission.submitted_at >= since)
    submissions_by_tactic: dict[str, set[int]] = {}
    for submission_id, tactic in query.all():
        submissions_by_tactic.setdefault(tactic, set()).add(submission_id)
    return {
        tactic: len(submission_ids)
        for tactic, submission_ids in submissions_by_tactic.items()
    }


def _ranked_counts(counts: dict[str, int]) -> list[CountItem]:
    return [
        CountItem(name=name, count=count)
        for name, count in sorted(
            counts.items(),
            key=lambda item: (-item[1], item[0]),
        )[:10]
    ]


def _network_context(
    db: Session,
    organization: Organization | None,
    org_id: int,
) -> NetworkContextOut | None:
    if organization is None or organization.share_with_network is not True:
        return None
    if not settings.CENTRAL_SERVER_URL or not settings.CENTRAL_API_KEY:
        return NetworkContextOut(
            enabled=True,
            available=False,
            error="Central aggregate service is not configured",
        )
    try:
        with CentralClient() as central:
            stats = central.get_intel_stats()
        central_technique_counts = {
            item["technique_id"]: int(item["count"])
            for item in stats.get("by_technique", [])
        }
        tactics = {
            technique_id: tactic
            for technique_id, tactic in db.query(
                MitreTechnique.id,
                MitreTechnique.tactic,
            ).all()
        }
        network_counts: dict[str, int] = {}
        for technique_id, count in central_technique_counts.items():
            tactic = tactics.get(technique_id)
            if tactic is not None:
                network_counts[tactic] = network_counts.get(tactic, 0) + count

        local_counts = _tactic_counts(db, org_id, since=None)
        all_tactics = sorted(set(local_counts) | set(network_counts))
        return NetworkContextOut(
            enabled=True,
            available=True,
            central_total=int(stats.get("total", 0)),
            by_tactic=[
                NetworkTacticComparison(
                    tactic=tactic,
                    local_count=local_counts.get(tactic, 0),
                    network_count=network_counts.get(tactic, 0),
                )
                for tactic in all_tactics
            ],
        )
    except (
        CentralClientConfigurationError,
        CentralRequestError,
        CentralUnavailableError,
        KeyError,
        TypeError,
        ValueError,
    ):
        logger.warning("Central analytics aggregates unavailable", exc_info=True)
        return NetworkContextOut(
            enabled=True,
            available=False,
            error="Central aggregate service is unavailable",
        )


@router.get("/overview", response_model=AnalyticsOverview)
def analytics_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AnalyticsOverview:
    """Return recent org analytics, active rule-based warnings, and opt-in aggregates."""
    now = datetime.now(timezone.utc)
    org_id = current_user.org_id
    organization = db.get(Organization, org_id)
    risk_counts = {
        band.value: count
        for band, count in (
            db.query(RiskScore.band, func.count(RiskScore.id))
            .join(RawSubmission, RawSubmission.id == RiskScore.submission_id)
            .join(User, User.id == RawSubmission.user_id)
            .filter(User.org_id == org_id)
            .group_by(RiskScore.band)
            .all()
        )
    }
    risk_distribution = [
        CountItem(name=band.value, count=risk_counts.get(band.value, 0))
        for band in RiskBand
    ]

    tactics_7d = _tactic_counts(db, org_id, since=now - timedelta(days=7))
    tactics_30d = _tactic_counts(db, org_id, since=now - timedelta(days=30))

    enrichment_rows = (
        db.query(
            EnrichmentResult.submission_id,
            EnrichmentResult.ioc_type,
            EnrichmentResult.ioc_value,
            EnrichmentResult.reputation_score,
        )
        .join(RawSubmission, RawSubmission.id == EnrichmentResult.submission_id)
        .join(User, User.id == RawSubmission.user_id)
        .filter(
            User.org_id == org_id,
            EnrichmentResult.status == EnrichmentStatus.complete,
            EnrichmentResult.reputation_score.is_not(None),
        )
        .all()
    )
    ioc_reputation: dict[tuple[int, str, str], list[int]] = {}
    for submission_id, ioc_type, ioc_value, score in enrichment_rows:
        key = (
            submission_id,
            ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type),
            ioc_value,
        )
        ioc_reputation.setdefault(key, []).append(int(score))
    enriched_iocs = len(ioc_reputation)
    non_clean_iocs = sum(
        1
        for scores in ioc_reputation.values()
        if any(score > 0 for score in scores)
    )

    trend_start = datetime.combine(
        (now - timedelta(days=29)).date(),
        time.min,
        tzinfo=timezone.utc,
    )
    trend_rows = (
        db.query(RawSubmission.submitted_at, RiskScore.score)
        .join(RiskScore, RiskScore.submission_id == RawSubmission.id)
        .join(User, User.id == RawSubmission.user_id)
        .filter(
            User.org_id == org_id,
            RawSubmission.submitted_at >= trend_start,
        )
        .all()
    )
    daily_scores: dict[str, list[int]] = {}
    for submitted_at, score in trend_rows:
        bucket = submitted_at.date().isoformat()
        daily_scores.setdefault(bucket, []).append(score)
    trend = []
    for offset in range(30):
        day = (trend_start + timedelta(days=offset)).date().isoformat()
        scores = daily_scores.get(day, [])
        trend.append(
            RiskTrendItem(
                date=day,
                average_score=round(sum(scores) / len(scores), 2) if scores else 0.0,
                submissions=len(scores),
            )
        )

    warning_cutoff = now - timedelta(hours=settings.WARNING_WINDOW_HOURS)
    warning_rows = (
        db.query(EarlyWarning)
        .filter(
            EarlyWarning.org_id == org_id,
            EarlyWarning.triggered_at >= warning_cutoff,
        )
        .order_by(EarlyWarning.triggered_at.desc())
        .all()
    )
    return AnalyticsOverview(
        risk_band_distribution=risk_distribution,
        top_mitre_tactics={
            "last_7_days": _ranked_counts(tactics_7d),
            "last_30_days": _ranked_counts(tactics_30d),
        },
        enrichment_hit_rate=(
            round(100 * non_clean_iocs / enriched_iocs, 2)
            if enriched_iocs
            else 0.0
        ),
        enriched_iocs=enriched_iocs,
        non_clean_iocs=non_clean_iocs,
        average_risk_score_trend=trend,
        network_context=_network_context(db, organization, org_id),
        active_warnings=[
            ActiveWarningOut(
                id=warning.id,
                triggered_at=warning.triggered_at.isoformat(),
                description=warning.description,
                submission_ids=warning.submission_ids,
            )
            for warning in warning_rows
        ],
    )
