"""Rule-based warnings from recent high/critical submissions."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.early_warning import EarlyWarning
from app.models.mitre_technique import MitreTechnique
from app.models.organization import Organization
from app.models.raw_submission import RawSubmission
from app.models.risk_score import RiskBand, RiskScore
from app.models.rule import Finding, Rule
from app.models.user import User

logger = logging.getLogger(__name__)


def scan_early_warnings(
    db: Session,
    *,
    now: datetime | None = None,
    window_hours: int | None = None,
    threshold: int | None = None,
) -> list[EarlyWarning]:
    """Upsert tactic/technique warnings for qualifying submissions in the window."""
    current_time = now or datetime.now(timezone.utc)
    hours = window_hours if window_hours is not None else settings.WARNING_WINDOW_HOURS
    minimum_count = threshold if threshold is not None else settings.WARNING_THRESHOLD
    cutoff = current_time - timedelta(hours=hours)

    rows = (
        db.query(
            User.org_id,
            RawSubmission.id,
            Rule.mitre_technique_id,
            MitreTechnique.tactic,
            MitreTechnique.name,
        )
        .join(RawSubmission, RawSubmission.user_id == User.id)
        .join(RiskScore, RiskScore.submission_id == RawSubmission.id)
        .join(Finding, Finding.submission_id == RawSubmission.id)
        .join(Rule, Rule.id == Finding.rule_id)
        .join(MitreTechnique, MitreTechnique.id == Rule.mitre_technique_id)
        .filter(
            RawSubmission.submitted_at >= cutoff,
            RiskScore.band.in_([RiskBand.high, RiskBand.critical]),
        )
        .all()
    )

    matched_submissions: dict[tuple[int, str, str], set[int]] = {}
    labels: dict[tuple[int, str, str], str] = {}
    for org_id, submission_id, technique_id, tactic, technique_name in rows:
        tactic_key = (org_id, "tactic", tactic)
        technique_key = (org_id, "technique", technique_id)
        matched_submissions.setdefault(tactic_key, set()).add(submission_id)
        matched_submissions.setdefault(technique_key, set()).add(submission_id)
        labels[tactic_key] = tactic
        labels[technique_key] = f"{technique_id} — {technique_name}"

    created_or_updated: list[EarlyWarning] = []
    for key, ids in matched_submissions.items():
        if len(ids) < minimum_count:
            continue
        org_id, kind, indicator = key
        organization = db.get(Organization, org_id)
        if organization is None:
            continue
        warning_key = f"{org_id}:{kind}:{indicator}"
        warning = (
            db.query(EarlyWarning)
            .filter(EarlyWarning.warning_key == warning_key)
            .one_or_none()
        )
        description = (
            f"{len(ids)} high/critical-risk submissions in the last {hours} hours "
            f"share MITRE {kind} {labels[key]} (threshold: {minimum_count})."
        )
        if warning is None:
            warning = EarlyWarning(
                org_id=org_id,
                warning_key=warning_key,
                description=description,
                submission_ids=sorted(ids),
                triggered_at=current_time,
            )
            db.add(warning)
        else:
            warning.description = description
            warning.submission_ids = sorted(ids)
            warning.triggered_at = current_time
        created_or_updated.append(warning)

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not persist early-warning scan results")
        raise
    return created_or_updated


def scan_early_warnings_background() -> None:
    from app.core.database import SessionLocal

    db = SessionLocal()
    try:
        scan_early_warnings(db)
    finally:
        db.close()
