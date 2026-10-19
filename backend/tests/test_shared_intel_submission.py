"""Tests that outbound sharing is queued after local submission processing."""
from fastapi import BackgroundTasks

from app.api.v1.endpoints.submissions import SubmissionCreate, create_submission
from app.models.organization import Organization
from app.models.raw_submission import NetworkSyncStatus, RawSubmission
from app.models.user import User, UserRole


def test_shared_intel_delivery_is_queued_after_local_evaluation(
    db_session,
    monkeypatch,
):
    organization = Organization(
        id=1,
        name="Queue Test Org",
        share_with_network=True,
    )
    db_session.add(organization)
    db_session.flush()
    user = User(
        org_id=organization.id,
        email="queue-test@example.org",
        hashed_password="test-hash",
        role=UserRole.analyst,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    class NoEmbedding:
        @staticmethod
        def embed(_text):
            return None

    monkeypatch.setattr(
        "app.embeddings.client.get_embeddings_client",
        lambda: NoEmbedding(),
    )
    monkeypatch.setattr(
        "app.api.v1.endpoints.submissions.correlate_submission_background",
        lambda *_args: None,
    )

    def queue_sharing(submission_id, organization_id):
        return None

    monkeypatch.setattr(
        "app.api.v1.endpoints.submissions.share_submission_background",
        queue_sharing,
    )
    background_tasks = BackgroundTasks()

    response = create_submission(
        SubmissionCreate(raw_text="Suspicious encoded command"),
        background_tasks=background_tasks,
        db=db_session,
        current_user=user,
    )

    assert response.id is not None
    queued = [(task.func, task.args) for task in background_tasks.tasks]
    assert queued[0][0].__name__ == "<lambda>"
    assert queued[1][0] is queue_sharing
    share_args = queued[1][1]
    assert share_args == (response.id, organization.id)
    saved_submission = db_session.get(RawSubmission, response.id)
    assert saved_submission.network_sync_status == NetworkSyncStatus.pending


def test_opted_out_org_does_not_queue_central_submission(db_session, monkeypatch):
    organization = Organization(
        id=1,
        name="Opt Out Queue Test Org",
        share_with_network=False,
    )
    db_session.add(organization)
    db_session.flush()
    user = User(
        org_id=organization.id,
        email="opt-out-queue@example.org",
        hashed_password="test-hash",
        role=UserRole.analyst,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    class NoEmbedding:
        @staticmethod
        def embed(_text):
            return None

    monkeypatch.setattr(
        "app.embeddings.client.get_embeddings_client",
        lambda: NoEmbedding(),
    )
    monkeypatch.setattr(
        "app.api.v1.endpoints.submissions.correlate_submission_background",
        lambda *_args: None,
    )
    background_tasks = BackgroundTasks()

    create_submission(
        SubmissionCreate(raw_text="An opted-out report"),
        background_tasks=background_tasks,
        db=db_session,
        current_user=user,
    )

    assert len(background_tasks.tasks) == 2
    assert background_tasks.tasks[0].func.__name__ == "<lambda>"
    assert background_tasks.tasks[1].func.__name__ == (
        "compute_submission_risk_score_background"
    )
