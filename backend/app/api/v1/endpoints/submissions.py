"""
Submissions endpoints.

POST /api/submissions          – ingest + sanitize a security artifact
GET  /api/submissions          – list (paginated; user-scoped unless admin)
GET  /api/submissions/{id}     – fetch single submission
"""
from __future__ import annotations

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.models.raw_submission import (
    EmbeddingStatus,
    RawSubmission,
    SanitizationStatus,
    SourceType,
)
from app.models.rule import Finding, Rule, Severity
from app.models.user import User, UserRole
from app.rules.evaluator import evaluate_rule
from app.sanitization.sanitizer import sanitize

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
    findings_by_severity: FindingSeveritySummary = FindingSeveritySummary()

    model_config = {"from_attributes": True}


class SubmissionDetail(SubmissionOut):
    """Extended view that includes the raw text (for the owner or admin)."""
    raw_text: str


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
    return SubmissionOut(
        id=sub.id,
        user_id=sub.user_id,
        source_type=sub.source_type,
        submitted_at=sub.submitted_at.isoformat(),
        sanitization_status=sub.sanitization_status,
        sanitized_text=sub.sanitized_text,
        embedding_status=sub.embedding_status,
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


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=SubmissionDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest and sanitize a security artifact",
)
def create_submission(
    body: SubmissionCreate,
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
    try:
        from app.embeddings.client import get_embeddings_client  # local import avoids circular deps
        emb_client = get_embeddings_client()
        if submission.sanitized_text:
            vector = emb_client.embed(submission.sanitized_text)
            if vector is not None:
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
