"""Tests for recurring-pattern scanning and campaign summaries."""
from datetime import datetime, timedelta, timezone

from app.api.deps import get_current_user
from app.correlation.campaigns import (
    build_campaign_summary,
    scan_recurring_memory_nodes,
)
from app.main import app
from app.models.memory import (
    CorrelationLink,
    LinkReason,
    MemoryNode,
    MemoryNodeStatus,
    SignatureType,
)
from app.models.raw_submission import RawSubmission
from app.models.rule import Rule
from app.models.user import User


def _make_node(db_session, *, last_seen, is_recurring=False):
    node = MemoryNode(
        signature_type=SignatureType.mitre_technique,
        signature_key="T1059",
        first_seen=last_seen,
        last_seen=last_seen,
        occurrence_count=1,
        status=MemoryNodeStatus.active,
        is_recurring=is_recurring,
        recurrence_window_days=30,
        recurrence_threshold=3,
    )
    db_session.add(node)
    db_session.flush()
    return node


def _add_link(db_session, user, node, linked_at):
    submission = RawSubmission(
        user_id=user.id,
        raw_text="test submission",
        sanitized_text="test submission",
    )
    db_session.add(submission)
    db_session.flush()
    db_session.add(
        CorrelationLink(
            memory_node_id=node.id,
            submission_id=submission.id,
            linked_at=linked_at,
            link_reason=LinkReason.shared_technique,
        )
    )


def test_scan_marks_node_recurring_at_recent_link_threshold(db_session):
    now = datetime(2026, 10, 4, tzinfo=timezone.utc)
    user = User(email="campaign-threshold@test.com", hashed_password="unused")
    db_session.add(user)
    db_session.flush()
    node = _make_node(db_session, last_seen=now - timedelta(days=1))
    for days_ago in (1, 2, 3, 40):
        _add_link(db_session, user, node, now - timedelta(days=days_ago))
    db_session.flush()

    result = scan_recurring_memory_nodes(db_session, now=now)

    assert result == {"scanned": 1, "recurring": 1, "dormant": 0}
    assert node.is_recurring is True
    assert node.status == MemoryNodeStatus.active


def test_scan_marks_old_node_dormant_without_recent_links(db_session):
    now = datetime(2026, 10, 4, tzinfo=timezone.utc)
    user = User(email="campaign-dormant@test.com", hashed_password="unused")
    db_session.add(user)
    db_session.flush()
    node = _make_node(
        db_session,
        last_seen=now - timedelta(days=31),
        is_recurring=True,
    )
    _add_link(db_session, user, node, now - timedelta(days=31))
    db_session.flush()

    result = scan_recurring_memory_nodes(db_session, now=now)

    assert result == {"scanned": 1, "recurring": 0, "dormant": 1}
    assert node.status == MemoryNodeStatus.dormant
    assert node.is_recurring is False


def test_campaign_summary_includes_signature_count_and_window(db_session):
    node = MemoryNode(
        signature_type=SignatureType.mitre_technique,
        signature_key="T1059",
        recurrence_window_days=30,
    )

    assert build_campaign_summary(node, 4) == "Technique T1059 observed 4 times in 30 days"
    assert build_campaign_summary(node, 1) == "Technique T1059 observed 1 time in 30 days"


def test_campaigns_endpoint_returns_recent_count_and_summary(client, db_session):
    now = datetime.now(timezone.utc)
    user = User(email="campaign-api@test.com", hashed_password="unused")
    db_session.add(user)
    db_session.flush()
    node = _make_node(
        db_session,
        last_seen=now,
        is_recurring=True,
    )
    for days_ago in (1, 2, 3):
        _add_link(db_session, user, node, now - timedelta(days=days_ago))
    db_session.commit()
    app.dependency_overrides[get_current_user] = lambda: user

    response = client.get("/api/memory/campaigns")

    assert response.status_code == 200
    campaigns = response.json()
    assert len(campaigns) == 1
    assert campaigns[0]["occurrence_count"] == 3
    assert campaigns[0]["summary"] == "Technique T1059 observed 3 times in 30 days"


def test_dashboard_summary_counts_active_campaigns(client, db_session):
    now = datetime.now(timezone.utc)
    user = User(email="campaign-dashboard@test.com", hashed_password="unused")
    db_session.add(user)
    db_session.flush()
    node = _make_node(db_session, last_seen=now, is_recurring=True)
    for days_ago in (1, 2, 3):
        _add_link(db_session, user, node, now - timedelta(days=days_ago))
    db_session.commit()
    app.dependency_overrides[get_current_user] = lambda: user

    response = client.get("/api/dashboard/summary")

    assert response.status_code == 200
    assert response.json()["active_campaign_count"] == 1


def test_demo_seed_creates_recurring_campaigns_idempotently(db_session):
    from app.rules.seed_rules import SEED_RULES
    from scripts.seed_demo import _seed_campaign_submissions

    user = User(email="campaign-seed@test.com", hashed_password="unused")
    db_session.add(user)
    for rule_data in SEED_RULES:
        db_session.add(
            Rule(
                name=rule_data["name"],
                description=rule_data.get("description"),
                condition_json=rule_data["condition_json"],
                severity=rule_data["severity"],
                mitre_technique_id=rule_data.get("mitre_technique_id"),
                is_active=True,
            )
        )
    db_session.commit()
    now = datetime(2026, 10, 4, tzinfo=timezone.utc)

    first_created = _seed_campaign_submissions(
        db_session,
        user,
        now=now,
        embedding_client=type("NoEmbedding", (), {"embed": lambda self, text: None})(),
    )
    recurring_nodes = (
        db_session.query(MemoryNode)
        .filter(MemoryNode.is_recurring.is_(True))
        .all()
    )
    second_created = _seed_campaign_submissions(
        db_session,
        user,
        now=now,
        embedding_client=type("NoEmbedding", (), {"embed": lambda self, text: None})(),
    )

    assert first_created == 6
    assert len(recurring_nodes) >= 4
    assert second_created == 0
    assert db_session.query(CorrelationLink).count() >= 12
