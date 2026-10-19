"""Organization-local controls and delivery status for central sharing."""
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin
from app.core.database import get_db
from app.models.organization import Organization
from app.models.raw_submission import NetworkSyncStatus, RawSubmission
from app.models.user import User

router = APIRouter(prefix="/network", tags=["network sharing"])


class NetworkSettingsUpdate(BaseModel):
    share_with_network: bool


class NetworkSettingsOut(BaseModel):
    share_with_network: bool
    last_sync_status: str | None
    last_sync_error: str | None
    last_synced_at: datetime | None
    submissions_shared: int


def _settings_for_organization(
    organization: Organization,
    db: Session,
) -> NetworkSettingsOut:
    latest = (
        db.query(
            RawSubmission.network_sync_status,
            RawSubmission.network_sync_error,
            RawSubmission.network_synced_at,
        )
        .join(User, RawSubmission.user_id == User.id)
        .filter(User.org_id == organization.id)
        .filter(RawSubmission.network_sync_status != NetworkSyncStatus.not_shared)
        .order_by(
            RawSubmission.network_synced_at.desc().nullslast(),
            RawSubmission.id.desc(),
        )
        .first()
    )
    shared_count = (
        db.query(func.count(RawSubmission.id))
        .join(User, RawSubmission.user_id == User.id)
        .filter(User.org_id == organization.id)
        .filter(
            RawSubmission.network_sync_status.in_(
                [NetworkSyncStatus.shared, NetworkSyncStatus.duplicate]
            )
        )
        .scalar()
    )
    return NetworkSettingsOut(
        share_with_network=organization.share_with_network,
        last_sync_status=latest.network_sync_status.value if latest else None,
        last_sync_error=latest.network_sync_error if latest else None,
        last_synced_at=latest.network_synced_at if latest else None,
        submissions_shared=int(shared_count or 0),
    )


@router.get("/settings", response_model=NetworkSettingsOut)
def get_network_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> NetworkSettingsOut:
    return _settings_for_organization(current_user.organization, db)


@router.put("/settings", response_model=NetworkSettingsOut)
def update_network_settings(
    body: NetworkSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> NetworkSettingsOut:
    organization = (
        db.query(Organization)
        .filter(Organization.id == current_user.org_id)
        .with_for_update()
        .one()
    )
    organization.share_with_network = body.share_with_network
    db.commit()
    db.refresh(organization)
    return _settings_for_organization(organization, db)
