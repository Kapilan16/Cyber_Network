"""Organization admin API tests for network contribution settings."""
from datetime import datetime, timedelta, timezone

from app.core.security import create_access_token, hash_password
from app.models.organization import Organization
from app.models.raw_submission import NetworkSyncStatus, RawSubmission
from app.models.user import User, UserRole


def _login_headers(user: User) -> dict[str, str]:
    token = create_access_token(user.email, user.role.value)
    return {"Authorization": f"Bearer {token}"}


def test_admin_can_read_and_update_org_network_settings(client, db_session):
    organization = Organization(id=1, name="Settings Test Org", share_with_network=False)
    db_session.add(organization)
    db_session.flush()
    admin = User(
        org_id=organization.id,
        email="network-admin@test.example",
        hashed_password=hash_password("test-password"),
        role=UserRole.admin,
    )
    db_session.add(admin)
    db_session.flush()
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            RawSubmission(
                user_id=admin.id,
                raw_text="accepted",
                network_sync_status=NetworkSyncStatus.shared,
                network_synced_at=now,
            ),
            RawSubmission(
                user_id=admin.id,
                raw_text="duplicate retry",
                network_sync_status=NetworkSyncStatus.duplicate,
                network_synced_at=now,
            ),
            RawSubmission(
                user_id=admin.id,
                raw_text="failed",
                network_sync_status=NetworkSyncStatus.failed,
                network_sync_error="Central server unavailable",
                network_synced_at=now + timedelta(seconds=1),
            ),
        ]
    )
    db_session.commit()
    headers = _login_headers(admin)

    current = client.get("/api/network/settings", headers=headers)
    assert current.status_code == 200
    assert current.json()["share_with_network"] is False
    assert current.json()["submissions_shared"] == 2
    assert current.json()["last_sync_status"] == "failed"
    assert current.json()["last_sync_error"] == "Central server unavailable"

    updated = client.put(
        "/api/network/settings",
        headers=headers,
        json={"share_with_network": True},
    )
    assert updated.status_code == 200
    assert updated.json()["share_with_network"] is True
    assert updated.json()["submissions_shared"] == 2


def test_analyst_cannot_read_or_change_network_settings(client, db_session):
    organization = Organization(id=1, name="Analyst Settings Test Org")
    db_session.add(organization)
    db_session.flush()
    analyst = User(
        org_id=organization.id,
        email="network-analyst@test.example",
        hashed_password=hash_password("test-password"),
        role=UserRole.analyst,
    )
    db_session.add(analyst)
    db_session.commit()
    headers = _login_headers(analyst)

    assert client.get("/api/network/settings", headers=headers).status_code == 403
    assert client.put(
        "/api/network/settings",
        headers=headers,
        json={"share_with_network": True},
    ).status_code == 403
