"""Background queue for sequential local threat-intelligence enrichment."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.enrichment.client import EnrichmentError, ThreatIntelClient
from app.models.enrichment import EnrichmentResult, EnrichmentStatus
from app.models.raw_submission import RawSubmission
from app.risk.service import compute_submission_risk_score

logger = logging.getLogger(__name__)


def process_enrichment_results(
    result_ids: list[int],
    *,
    session_factory: Callable[[], Session] = SessionLocal,
    client: ThreatIntelClient | None = None,
) -> None:
    """Process queued records one by one; lookup failures never affect submissions."""
    if not result_ids:
        return
    db = session_factory()
    threat_client = client or ThreatIntelClient()
    try:
        results = (
            db.query(EnrichmentResult)
            .filter(
                EnrichmentResult.id.in_(result_ids),
                EnrichmentResult.status == EnrichmentStatus.pending,
            )
            .order_by(EnrichmentResult.id)
            .all()
        )
        from app.enrichment.iocs import extract_iocs

        for result in results:
            submission = (
                db.query(RawSubmission)
                .filter(RawSubmission.id == result.submission_id)
                .first()
            )
            if submission is None:
                _fail(result, "Submission no longer exists")
                db.commit()
                continue

            ioc = next(
                (
                    item
                    for item in extract_iocs(submission.sanitized_text or "")
                    if item.ioc_type == result.ioc_type.value
                    and item.ioc_value == result.ioc_value
                ),
                None,
            )
            if ioc is not None and not ioc.externally_queryable:
                _fail(result, "Non-public IOC was not sent to providers")
                db.commit()
                continue

            try:
                response = threat_client.query(
                    result.source.value,
                    result.ioc_type.value,
                    result.ioc_value,
                )
                result.reputation_score = response.reputation_score
                result.raw_response_summary = response.raw_response_summary
                result.status = EnrichmentStatus.complete
            except EnrichmentError as exc:
                logger.warning(
                    "Enrichment lookup failed for submission %s IOC %s via %s: %s",
                    result.submission_id,
                    result.ioc_value,
                    result.source.value,
                    exc,
                )
                _fail(result, str(exc))
            except Exception:
                logger.exception(
                    "Unexpected enrichment error for result %s",
                    result.id,
                )
                _fail(result, "Unexpected provider error")
            result.queried_at = datetime.now(timezone.utc)
            db.commit()
        for submission_id in sorted({result.submission_id for result in results}):
            compute_submission_risk_score(db, submission_id)
        db.commit()
        try:
            from app.analytics.warnings import scan_early_warnings

            scan_early_warnings(db)
        except Exception:
            logger.exception(
                "Enrichment and risk scores persisted, but early-warning scan failed"
            )
    except Exception:
        db.rollback()
        logger.exception("Unable to process enrichment queue")
    finally:
        db.close()


def _fail(result: EnrichmentResult, reason: str) -> None:
    result.status = EnrichmentStatus.failed
    result.reputation_score = None
    result.raw_response_summary = {"error": reason[:200]}
    result.queried_at = datetime.now(timezone.utc)
