"""
Dashboard summary endpoint.

GET /api/dashboard/summary — returns aggregate counts for the analyst dashboard.

Scope:
- Analysts see their own data only.
- Admins see all data across all users.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.mitre_technique import MitreTechnique
from app.models.raw_submission import RawSubmission
from app.models.rule import Finding, Rule, Severity
from app.models.user import User, UserRole

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class TacticCount(BaseModel):
    tactic: str
    count: int


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DashboardSummary(BaseModel):
    submissions_today: int
    submissions_this_week: int
    total_submissions: int
    findings_by_severity: SeverityBreakdown
    open_findings_by_severity: SeverityBreakdown
    total_findings: int
    top_tactics_this_week: List[TacticCount]
    total_rules: int
    active_rules: int
    embedding_complete_count: int
    embedding_pending_count: int


# ── Route ─────────────────────────────────────────────────────────────────────

@router.get(
    "/summary",
    response_model=DashboardSummary,
    summary="Aggregate dashboard statistics",
)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DashboardSummary:
    is_admin = current_user.role == UserRole.admin

    # Time windows (UTC)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start  = today_start - timedelta(days=today_start.weekday())

    # ── Submission counts ─────────────────────────────────────────────────
    sub_q = db.query(RawSubmission)
    if not is_admin:
        sub_q = sub_q.filter(RawSubmission.user_id == current_user.id)

    total_submissions     = sub_q.count()
    submissions_today     = sub_q.filter(RawSubmission.submitted_at >= today_start).count()
    submissions_this_week = sub_q.filter(RawSubmission.submitted_at >= week_start).count()

    # ── Embedding status counts ───────────────────────────────────────────
    from app.models.raw_submission import EmbeddingStatus
    embedding_complete_count = sub_q.filter(
        RawSubmission.embedding_status == EmbeddingStatus.complete
    ).count()
    embedding_pending_count = sub_q.filter(
        RawSubmission.embedding_status == EmbeddingStatus.pending
    ).count()

    # ── Findings by severity ──────────────────────────────────────────────
    finding_q = db.query(Finding.severity, func.count(Finding.id).label("n"))
    if not is_admin:
        finding_q = finding_q.join(
            RawSubmission, Finding.submission_id == RawSubmission.id
        ).filter(RawSubmission.user_id == current_user.id)
    rows = finding_q.group_by(Finding.severity).all()

    sev_map: Dict[str, int] = {r.severity.value: r.n for r in rows}
    findings_by_severity = SeverityBreakdown(
        critical=sev_map.get("critical", 0),
        high=sev_map.get("high", 0),
        medium=sev_map.get("medium", 0),
        low=sev_map.get("low", 0),
    )
    total_findings = sum(sev_map.values())

    # ── Top MITRE tactics this week ───────────────────────────────────────
    tactics_q = (
        db.query(
            MitreTechnique.tactic,
            func.count(Finding.id).label("n"),
        )
        .join(Rule, Finding.rule_id == Rule.id)
        .join(MitreTechnique, Rule.mitre_technique_id == MitreTechnique.id)
        .filter(Finding.created_at >= week_start)
    )
    if not is_admin:
        tactics_q = tactics_q.join(
            RawSubmission, Finding.submission_id == RawSubmission.id
        ).filter(RawSubmission.user_id == current_user.id)

    top_tactics = (
        tactics_q.group_by(MitreTechnique.tactic)
        .order_by(func.count(Finding.id).desc())
        .limit(6)
        .all()
    )

    # ── Rule counts (global) ──────────────────────────────────────────────
    total_rules  = db.query(func.count(Rule.id)).scalar() or 0
    active_rules = db.query(func.count(Rule.id)).filter(Rule.is_active == True).scalar() or 0  # noqa: E712

    return DashboardSummary(
        submissions_today=submissions_today,
        submissions_this_week=submissions_this_week,
        total_submissions=total_submissions,
        findings_by_severity=findings_by_severity,
        open_findings_by_severity=findings_by_severity,
        total_findings=total_findings,
        top_tactics_this_week=[TacticCount(tactic=t.tactic, count=t.n) for t in top_tactics],
        total_rules=total_rules,
        active_rules=active_rules,
        embedding_complete_count=embedding_complete_count,
        embedding_pending_count=embedding_pending_count,
    )
