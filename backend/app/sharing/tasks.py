"""Background handoff of explicitly opted-in sanitized intelligence."""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import joinedload

from app.central_client import (
    CentralClient,
    CentralClientConfigurationError,
    CentralRequestError,
    CentralUnavailableError,
)
from app.core.config import settings
from app.core.database import SessionLocal
from app.models.mitre_technique import MitreTechnique
from app.models.organization import Organization
from app.models.raw_submission import NetworkSyncStatus, RawSubmission
from app.models.rule import Finding
from app.sharing.payload import SharingOptInRequiredError, build_shared_intel_payload

logger = logging.getLogger(__name__)


def _set_sync_result(
    db,
    submission_id: int,
    status: NetworkSyncStatus,
    *,
    error: str | None = None,
) -> None:
    submission = (
        db.query(RawSubmission)
        .filter(RawSubmission.id == submission_id)
        .first()
    )
    if submission is None:
        logger.error("Cannot record network sync result for missing submission %s", submission_id)
        return
    submission.network_sync_status = status
    submission.network_sync_error = error
    submission.network_synced_at = (
        datetime.now(timezone.utc)
        if status != NetworkSyncStatus.not_shared
        else None
    )
    db.commit()


def share_submission_background(submission_id: int, organization_id: int) -> None:
    """Build and submit a payload in the background, never failing local intake."""
    db = SessionLocal()
    try:
        if not settings.CENTRAL_SERVER_URL or not settings.CENTRAL_API_KEY:
            _set_sync_result(
                db,
                submission_id,
                NetworkSyncStatus.failed,
                error="Central sharing is not configured",
            )
            logger.error(
                "Central sharing is not configured; submission %s was not sent",
                submission_id,
            )
            return

        organization = (
            db.query(Organization)
            .filter(Organization.id == organization_id)
            .first()
        )
        if organization is None:
            logger.error(
                "Cannot share submission %s: organization %s no longer exists",
                submission_id,
                organization_id,
            )
            _set_sync_result(
                db,
                submission_id,
                NetworkSyncStatus.failed,
                error="Local organization no longer exists",
            )
            return
        if organization.share_with_network is not True:
            _set_sync_result(
                db,
                submission_id,
                NetworkSyncStatus.not_shared,
            )
            logger.debug(
                "Organization %s has not opted in; skipping submission %s",
                organization_id,
                submission_id,
            )
            return

        submission = (
            db.query(RawSubmission)
            .filter(RawSubmission.id == submission_id)
            .first()
        )
        if submission is None:
            logger.error("Cannot share missing submission %s", submission_id)
            return

        findings = (
            db.query(Finding)
            .options(joinedload(Finding.rule))
            .filter(Finding.submission_id == submission_id)
            .all()
        )
        technique_ids = {
            finding.rule.mitre_technique_id
            for finding in findings
            if finding.rule is not None and finding.rule.mitre_technique_id
        }
        techniques = (
            db.query(MitreTechnique)
            .filter(MitreTechnique.id.in_(technique_ids))
            .all()
            if technique_ids
            else []
        )

        payload = build_shared_intel_payload(
            organization,
            submission,
            findings,
            techniques,
        )
        with CentralClient() as central:
            result = central.submit_intel(payload)
        _set_sync_result(
            db,
            submission_id,
            NetworkSyncStatus.duplicate
            if result.get("duplicate", False)
            else NetworkSyncStatus.shared,
        )
        logger.info(
            "Central sharing completed for submission %s (duplicate=%s)",
            submission_id,
            result.get("duplicate", False),
        )
    except SharingOptInRequiredError:
        logger.warning(
            "Opt-in changed while preparing submission %s; outbound sharing skipped",
            submission_id,
        )
        _set_sync_result(db, submission_id, NetworkSyncStatus.not_shared)
    except CentralUnavailableError as exc:
        _set_sync_result(
            db,
            submission_id,
            NetworkSyncStatus.failed,
            error=f"Central server unavailable after {exc.attempts} attempt(s)",
        )
        logger.warning(
            "Central server unavailable for submission %s after %s attempt(s); "
            "local processing remains complete",
            submission_id,
            exc.attempts,
        )
    except CentralRequestError as exc:
        _set_sync_result(
            db,
            submission_id,
            NetworkSyncStatus.failed,
            error=f"Central server rejected payload (HTTP {exc.status_code})",
        )
        logger.error(
            "Central server rejected submission %s with HTTP %s",
            submission_id,
            exc.status_code,
        )
    except CentralClientConfigurationError:
        _set_sync_result(
            db,
            submission_id,
            NetworkSyncStatus.failed,
            error="Central sharing configuration is invalid",
        )
        logger.error(
            "Central sharing is configured incompletely; submission %s was not sent",
            submission_id,
        )
    except Exception:
        _set_sync_result(
            db,
            submission_id,
            NetworkSyncStatus.failed,
            error="Unexpected central sharing failure",
        )
        logger.exception(
            "Unexpected central sharing failure for submission %s; "
            "local processing remains complete",
            submission_id,
        )
    finally:
        db.close()
