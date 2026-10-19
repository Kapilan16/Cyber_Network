"""Tests for persisted central-delivery outcomes."""
from app.models.organization import Organization
from app.models.raw_submission import NetworkSyncStatus, RawSubmission
from app.models.user import User, UserRole
from app.sharing.tasks import (
    CentralUnavailableError,
    share_submission_background,
)


def _make_submission(db_session):
    organization = Organization(
        id=1,
        name="Sync Status Test Org",
        share_with_network=True,
    )
    db_session.add(organization)
    db_session.flush()
    user = User(
        org_id=organization.id,
        email="sync-status@test.example",
        hashed_password="unused",
        role=UserRole.admin,
    )
    db_session.add(user)
    db_session.flush()
    submission = RawSubmission(
        user_id=user.id,
        raw_text="test submission",
        sanitized_text="sanitized test submission",
        network_sync_status=NetworkSyncStatus.pending,
    )
    db_session.add(submission)
    db_session.commit()
    return organization, submission


def test_successful_delivery_updates_submission_sync_state(
    db_session,
    monkeypatch,
):
    organization, submission = _make_submission(db_session)
    organization_id = organization.id
    submission_id = submission.id
    monkeypatch.setattr("app.sharing.tasks.SessionLocal", lambda: db_session)
    monkeypatch.setattr("app.sharing.tasks.settings.CENTRAL_SERVER_URL", "http://central")
    monkeypatch.setattr("app.sharing.tasks.settings.CENTRAL_API_KEY", "demo-key")
    monkeypatch.setattr(
        "app.sharing.tasks.build_shared_intel_payload",
        lambda *_args: {"sanitized_text": "safe"},
    )

    class Central:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def submit_intel(self, _payload):
            return {"duplicate": False}

    monkeypatch.setattr("app.sharing.tasks.CentralClient", Central)

    share_submission_background(submission_id, organization_id)

    saved = db_session.get(RawSubmission, submission_id)
    assert saved.network_sync_status == NetworkSyncStatus.shared
    assert saved.network_sync_error is None
    assert saved.network_synced_at is not None


def test_central_outage_is_visible_in_submission_sync_state(
    db_session,
    monkeypatch,
):
    organization, submission = _make_submission(db_session)
    organization_id = organization.id
    submission_id = submission.id
    monkeypatch.setattr("app.sharing.tasks.SessionLocal", lambda: db_session)
    monkeypatch.setattr("app.sharing.tasks.settings.CENTRAL_SERVER_URL", "http://central")
    monkeypatch.setattr("app.sharing.tasks.settings.CENTRAL_API_KEY", "demo-key")
    monkeypatch.setattr(
        "app.sharing.tasks.build_shared_intel_payload",
        lambda *_args: {"sanitized_text": "safe"},
    )

    class Central:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def submit_intel(self, _payload):
            raise CentralUnavailableError("private transport details", attempts=3)

    monkeypatch.setattr("app.sharing.tasks.CentralClient", Central)

    share_submission_background(submission_id, organization_id)

    saved = db_session.get(RawSubmission, submission_id)
    assert saved.network_sync_status == NetworkSyncStatus.failed
    assert saved.network_sync_error == "Central server unavailable after 3 attempt(s)"
    assert saved.network_synced_at is not None
