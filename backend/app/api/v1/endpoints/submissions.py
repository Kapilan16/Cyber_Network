"""
Submissions endpoints.

POST /api/submissions          – ingest + sanitize a security artifact
GET  /api/submissions          – list (paginated; user-scoped unless admin)
GET  /api/submissions/{id}     – fetch single submission
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import get_current_user
from app.correlation.engine import correlate_submission_background
from app.core.config import settings
from app.core.database import get_db
from app.enrichment.iocs import extract_iocs
from app.enrichment.tasks import process_enrichment_results
from app.models.enrichment import (
    EnrichmentResult,
    EnrichmentSource,
    EnrichmentStatus,
    IOCType,
)
from app.models.raw_submission import (
    EmbeddingStatus,
    NetworkSyncStatus,
    RawSubmission,
    SanitizationStatus,
    SourceType,
)
from app.models.risk_score import RiskBand, RiskScore
from app.models.recommendation import AiRecommendation, RecommendationStatus
from app.models.rule import Finding, Rule, Severity
from app.risk.service import compute_submission_risk_score_background
from app.recommendations.service import generate_recommendation_background
from app.models.user import User, UserRole
from app.rules.evaluator import evaluate_rule
from app.sanitization.sanitizer import sanitize
from app.sharing.tasks import share_submission_background

router = APIRouter()


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class SubmissionCreate(BaseModel):
    raw_text: str = Field(..., min_length=1, max_length=200_000)
    source_type: SourceType = SourceType.freeform


class SanitizationMeta(BaseModel):
    redaction_count: int
    flag_count: int
    was_truncated: bool
    warnings: List[str]


class FindingSeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class SubmissionOut(BaseModel):
    id: int
    user_id: int
    source_type: SourceType
    submitted_at: str        # ISO-8601
    sanitization_status: SanitizationStatus
    sanitized_text: Optional[str]
    sanitization_meta: Optional[SanitizationMeta] = None
    embedding_status: EmbeddingStatus
    risk_score: Optional[int] = None
    risk_band: Optional[RiskBand] = None
    findings_by_severity: FindingSeveritySummary = FindingSeveritySummary()

    model_config = {"from_attributes": True}


class SubmissionDetail(SubmissionOut):
    """Extended view that includes the raw text (for the owner or admin)."""
    raw_text: str


class EnrichmentResultOut(BaseModel):
    id: int
    submission_id: int
    ioc_type: IOCType
    ioc_value: str
    source: EnrichmentSource
    reputation_score: Optional[int]
    raw_response_summary: Optional[dict]
    queried_at: Optional[str]
    status: EnrichmentStatus


class EnrichmentTriggerResponse(BaseModel):
    submission_id: int
    iocs_detected: int
    enrichments_queued: int
    results: List[EnrichmentResultOut]


class RiskScoreOut(BaseModel):
    id: int
    submission_id: int
    score: int
    band: RiskBand
    components: dict
    computed_at: str


class RecommendationOut(BaseModel):
    id: int
    submission_id: int
    recommendation_text: Optional[str]
    suggested_actions: Optional[List[str]]
    confidence: Optional[float]
    generated_at: Optional[str]
    model_used: Optional[str]
    status: RecommendationStatus
    error: Optional[str]


def _recommendation_out(
    recommendation: AiRecommendation,
) -> RecommendationOut:
    return RecommendationOut(
        id=recommendation.id,
        submission_id=recommendation.submission_id,
        recommendation_text=recommendation.recommendation_text,
        suggested_actions=recommendation.suggested_actions,
        confidence=recommendation.confidence,
        generated_at=(
            recommendation.generated_at.isoformat()
            if recommendation.generated_at
            else None
        ),
        model_used=recommendation.model_used,
        status=recommendation.status,
        error=recommendation.error,
    )


class PaginatedSubmissions(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[SubmissionOut]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_ownership(submission: RawSubmission, current_user: User) -> None:
    """Raise 404 (not 403) if the submission doesn't belong to this user and
    they're not an admin. We use 404 to avoid leaking existence."""
    if current_user.role != UserRole.admin and submission.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found")


def _to_out(sub: RawSubmission, db: Session) -> SubmissionOut:
    severity_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.submission_id == sub.id)
        .group_by(Finding.severity)
        .all()
    )
    severity_counts = {severity.value: count for severity, count in severity_rows}
    risk_score = (
        db.query(RiskScore)
        .filter(RiskScore.submission_id == sub.id)
        .one_or_none()
    )
    return SubmissionOut(
        id=sub.id,
        user_id=sub.user_id,
        source_type=sub.source_type,
        submitted_at=sub.submitted_at.isoformat(),
        sanitization_status=sub.sanitization_status,
        sanitized_text=sub.sanitized_text,
        embedding_status=sub.embedding_status,
        risk_score=risk_score.score if risk_score else None,
        risk_band=risk_score.band if risk_score else None,
        findings_by_severity=FindingSeveritySummary(
            critical=severity_counts.get("critical", 0),
            high=severity_counts.get("high", 0),
            medium=severity_counts.get("medium", 0),
            low=severity_counts.get("low", 0),
        ),
    )


def _to_detail(sub: RawSubmission) -> SubmissionDetail:
    return SubmissionDetail(
        id=sub.id,
        user_id=sub.user_id,
        source_type=sub.source_type,
        submitted_at=sub.submitted_at.isoformat(),
        sanitization_status=sub.sanitization_status,
        sanitized_text=sub.sanitized_text,
        raw_text=sub.raw_text,
        embedding_status=sub.embedding_status,
    )


def _enrichment_out(result: EnrichmentResult) -> EnrichmentResultOut:
    return EnrichmentResultOut(
        id=result.id,
        submission_id=result.submission_id,
        ioc_type=result.ioc_type,
        ioc_value=result.ioc_value,
        source=result.source,
        reputation_score=result.reputation_score,
        raw_response_summary=result.raw_response_summary,
        queried_at=result.queried_at.isoformat() if result.queried_at else None,
        status=result.status,
    )


def _get_owned_submission(
    db: Session,
    submission_id: int,
    current_user: User,
) -> RawSubmission:
    submission = (
        db.query(RawSubmission)
        .filter(RawSubmission.id == submission_id)
        .first()
    )
    if submission is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Submission not found",
        )
    _check_ownership(submission, current_user)
    return submission


def _queue_risk_score(
    background_tasks: BackgroundTasks,
    submission_id: int,
    db: Session,
) -> None:
    background_tasks.add_task(
        compute_submission_risk_score_background,
        submission_id,
        session_factory=sessionmaker(
            bind=db.get_bind(),
            autoflush=False,
            autocommit=False,
        ),
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=SubmissionDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest and sanitize a security artifact",
)
def create_submission(
    body: SubmissionCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SubmissionDetail:
    """
    Accepts raw analyst text, runs the sanitization pipeline, and persists
    both the original and sanitized versions, evaluates active declarative
    rules, and attempts embedding. Submitted content is never executed as code.
    """
    result = sanitize(
        body.raw_text,
        redact_pii=settings.REDACT_PII,
        max_length=settings.MAX_SUBMISSION_LENGTH,
    )

    submission = RawSubmission(
        user_id=current_user.id,
        raw_text=body.raw_text,
        source_type=body.source_type,
        sanitized_text=result.sanitized_text,
        sanitization_status=result.status,
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)

    context = {
        "sanitized_text": submission.sanitized_text or "",
        "raw_text": submission.raw_text or "",
        "source_type": submission.source_type.value if submission.source_type else "",
    }
    active_rules = db.query(Rule).filter(Rule.is_active == True).all()  # noqa: E712
    for rule in active_rules:
        try:
            matched, snippet = evaluate_rule(rule.condition_json, context)
        except Exception:  # noqa: BLE001
            matched, snippet = False, ""
        if matched:
            db.add(Finding(
                submission_id=submission.id,
                rule_id=rule.id,
                matched_snippet=snippet[:500] if snippet else None,
                severity=rule.severity,
            ))
    db.commit()

    # ── Embed sanitized text (non-blocking) ───────────────────────────────
    # Embedding failure must never prevent the submission from being returned.
    index_vector = None
    try:
        from app.embeddings.client import get_embeddings_client  # local import avoids circular deps
        emb_client = get_embeddings_client()
        if submission.sanitized_text:
            vector = emb_client.embed(submission.sanitized_text)
            if vector is not None:
                index_vector = vector
                submission.embedding = (
                    json.dumps(vector) if db.bind.dialect.name == "sqlite" else vector
                )
                submission.embedding_status = EmbeddingStatus.complete
            else:
                submission.embedding_status = EmbeddingStatus.failed
        else:
            submission.embedding_status = EmbeddingStatus.failed
        db.commit()
        db.refresh(submission)
        if index_vector is not None:
            try:
                from app.search.faiss_index import get_faiss_index

                get_faiss_index().add(submission.id, index_vector)
            except Exception:
                import logging as _log
                _log.getLogger(__name__).exception(
                    "Could not add submission %s to FAISS index",
                    submission.id,
                )
    except Exception:  # noqa: BLE001
        import logging as _log
        _log.getLogger(__name__).warning(
            "Embedding step raised unexpectedly for submission %s — marking failed.",
            submission.id,
        )
        try:
            submission.embedding_status = EmbeddingStatus.failed
            db.commit()
        except Exception:  # noqa: BLE001
            pass

    background_tasks.add_task(correlate_submission_background, submission.id)
    organization = current_user.organization
    if organization is not None and organization.share_with_network is True:
        submission.network_sync_status = NetworkSyncStatus.pending
        submission.network_synced_at = datetime.now(timezone.utc)
        db.commit()
        background_tasks.add_task(
            share_submission_background,
            submission.id,
            organization.id,
        )
    _queue_risk_score(background_tasks, submission.id, db)

    # ──────────────────────────────────────────────────────────────────────
    detail = _to_detail(submission)
    detail.sanitization_meta = SanitizationMeta(
        redaction_count=result.redaction_count,
        flag_count=result.flag_count,
        was_truncated=result.was_truncated,
        warnings=result.warnings,
    )
    return detail


@router.get(
    "",
    response_model=PaginatedSubmissions,
    summary="List submissions (paginated, user-scoped)",
)
def list_submissions(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page"),
    source_type: Optional[SourceType] = Query(None, description="Filter by source type"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedSubmissions:
    """
    Admins see all submissions; analysts see only their own.
    Results are ordered newest-first.
    """
    q = db.query(RawSubmission)
    if current_user.role != UserRole.admin:
        q = q.filter(RawSubmission.user_id == current_user.id)
    if source_type:
        q = q.filter(RawSubmission.source_type == source_type)

    total = q.count()
    items = (
        q.order_by(RawSubmission.submitted_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedSubmissions(
        total=total,
        page=page,
        page_size=page_size,
        items=[_to_out(s, db) for s in items],
    )


@router.get(
    "/{submission_id}/risk-score",
    response_model=RiskScoreOut,
    summary="Get the persisted composite risk score for a submission",
)
def get_submission_risk_score(
    submission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RiskScoreOut:
    _get_owned_submission(db, submission_id, current_user)
    risk = (
        db.query(RiskScore)
        .filter(RiskScore.submission_id == submission_id)
        .one_or_none()
    )
    if risk is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk score is not available yet",
        )
    return RiskScoreOut(
        id=risk.id,
        submission_id=risk.submission_id,
        score=risk.score,
        band=risk.band,
        components=risk.components,
        computed_at=risk.computed_at.isoformat(),
    )


@router.get(
    "/{submission_id}/enrichment",
    response_model=List[EnrichmentResultOut],
    summary="List local IOC enrichment results for a submission",
)
def get_submission_enrichment(
    submission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[EnrichmentResultOut]:
    _get_owned_submission(db, submission_id, current_user)
    results = (
        db.query(EnrichmentResult)
        .filter(EnrichmentResult.submission_id == submission_id)
        .order_by(EnrichmentResult.id)
        .all()
    )
    return [_enrichment_out(result) for result in results]


@router.post(
    "/{submission_id}/enrich",
    response_model=EnrichmentTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue read-only threat-intelligence lookups for extracted IOCs",
)
def enrich_submission(
    submission_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnrichmentTriggerResponse:
    submission = _get_owned_submission(db, submission_id, current_user)
    if not submission.sanitized_text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Submission has no sanitized text to enrich",
        )

    iocs = extract_iocs(submission.sanitized_text)
    existing_rows = (
        db.query(EnrichmentResult)
        .filter(EnrichmentResult.submission_id == submission_id)
        .all()
    )
    by_key = {
        (row.ioc_type.value, row.ioc_value, row.source.value): row
        for row in existing_rows
    }
    queued_new: list[EnrichmentResult] = []
    queued_retry: list[int] = []
    providers = [(ioc, EnrichmentSource.virustotal) for ioc in iocs]
    providers.extend(
        (ioc, EnrichmentSource.abuseipdb)
        for ioc in iocs
        if ioc.ioc_type == "ip"
    )

    for ioc, source in providers:
        key = (ioc.ioc_type, ioc.ioc_value, source.value)
        result = by_key.get(key)
        if result is None:
            result = EnrichmentResult(
                submission_id=submission_id,
                ioc_type=IOCType(ioc.ioc_type),
                ioc_value=ioc.ioc_value,
                source=source,
                status=EnrichmentStatus.pending,
            )
            db.add(result)
            by_key[key] = result
            queued_new.append(result)
        elif result.status == EnrichmentStatus.failed:
            result.status = EnrichmentStatus.pending
            result.reputation_score = None
            result.raw_response_summary = None
            result.queried_at = None
            queued_retry.append(result.id)

    db.commit()
    queued_ids = [result.id for result in queued_new] + queued_retry
    if queued_ids:
        background_tasks.add_task(process_enrichment_results, queued_ids)
    else:
        _queue_risk_score(background_tasks, submission_id, db)

    results = (
        db.query(EnrichmentResult)
        .filter(EnrichmentResult.submission_id == submission_id)
        .order_by(EnrichmentResult.id)
        .all()
    )
    return EnrichmentTriggerResponse(
        submission_id=submission_id,
        iocs_detected=len(iocs),
        enrichments_queued=len(queued_ids),
        results=[_enrichment_out(result) for result in results],
    )


@router.post(
    "/{submission_id}/recommend",
    response_model=RecommendationOut,
    summary="Generate or retrieve an advisory analyst recommendation",
)
def recommend_submission(
    submission_id: int,
    background_tasks: BackgroundTasks,
    response: Response,
    regenerate: bool = Query(
        False,
        description="Explicitly replace a previous recommendation",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RecommendationOut:
    submission = _get_owned_submission(db, submission_id, current_user)
    if not submission.sanitized_text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Submission has no sanitized text for recommendation",
        )

    recommendation = (
        db.query(AiRecommendation)
        .filter(AiRecommendation.submission_id == submission_id)
        .with_for_update()
        .one_or_none()
    )
    if recommendation is not None:
        if recommendation.status == RecommendationStatus.pending:
            response.status_code = status.HTTP_202_ACCEPTED
            return _recommendation_out(recommendation)
        if not regenerate:
            response.status_code = status.HTTP_200_OK
            return _recommendation_out(recommendation)
        recommendation.status = RecommendationStatus.pending
        recommendation.recommendation_text = None
        recommendation.suggested_actions = None
        recommendation.confidence = None
        recommendation.generated_at = None
        recommendation.model_used = None
        recommendation.error = None
    else:
        recommendation = AiRecommendation(
            submission_id=submission_id,
            status=RecommendationStatus.pending,
        )
        db.add(recommendation)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # The unique submission key makes concurrent POSTs share one cache row.
        recommendation = (
            db.query(AiRecommendation)
            .filter(AiRecommendation.submission_id == submission_id)
            .one_or_none()
        )
        if recommendation is None:
            raise
        response.status_code = (
            status.HTTP_202_ACCEPTED
            if recommendation.status == RecommendationStatus.pending
            else status.HTTP_200_OK
        )
        return _recommendation_out(recommendation)

    db.refresh(recommendation)
    background_tasks.add_task(
        generate_recommendation_background,
        recommendation.id,
        session_factory=sessionmaker(
            bind=db.get_bind(),
            autoflush=False,
            autocommit=False,
        ),
    )
    response.status_code = status.HTTP_202_ACCEPTED
    return _recommendation_out(recommendation)


@router.get(
    "/{submission_id}/recommendation",
    response_model=RecommendationOut,
    summary="Get a submission's cached AI recommendation",
)
def get_submission_recommendation(
    submission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RecommendationOut:
    _get_owned_submission(db, submission_id, current_user)
    recommendation = (
        db.query(AiRecommendation)
        .filter(AiRecommendation.submission_id == submission_id)
        .one_or_none()
    )
    if recommendation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recommendation has not been requested",
        )
    return _recommendation_out(recommendation)


@router.get(
    "/{submission_id}",
    response_model=SubmissionDetail,
    summary="Get a single submission by ID",
)
def get_submission(
    submission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SubmissionDetail:
    sub = db.query(RawSubmission).filter(RawSubmission.id == submission_id).first()
    if sub is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found")
    _check_ownership(sub, current_user)
    return _to_detail(sub)
