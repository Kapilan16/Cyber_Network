"""Tests for long-term memory node read endpoints."""
from datetime import datetime, timezone

from app.api.deps import get_current_user
from app.core.database import get_db
from app.main import app
from app.models.memory import (
    CorrelationLink,
    LinkReason,
    MemoryNode,
    MemoryNodeStatus,
    SignatureType,
)
from app.models.raw_submission import RawSubmission
from app.models.rule import Finding, Rule, Severity
from app.models.user import User, UserRole


def _seed_memory_data(db_session):
    analyst = User(email="memory-analyst@test.com", hashed_password="unused")
    other_user = User(email="memory-other@test.com", hashed_password="unused")
    db_session.add_all([analyst, other_user])
    db_session.flush()

    owned_submission = RawSubmission(
        user_id=analyst.id,
        raw_text="owned raw text",
        sanitized_text="owned sanitized text",
    )
    other_submission = RawSubmission(
        user_id=other_user.id,
        raw_text="private raw text",
        sanitized_text="private sanitized text",
    )
    rule = Rule(name="Memory test rule", condition_json={"contains": "test"})
    db_session.add_all([owned_submission, other_submission, rule])
    db_session.flush()

    finding = Finding(
        submission_id=owned_submission.id,
        rule_id=rule.id,
        severity=Severity.high,
        matched_snippet="matched context",
    )
    shared_node = MemoryNode(
        signature_type=SignatureType.rule,
        signature_key=str(rule.id),
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 2, 1, tzinfo=timezone.utc),
        occurrence_count=2,
        status=MemoryNodeStatus.active,
        summary="Repeated test rule",
    )
    dormant_node = MemoryNode(
        signature_type=SignatureType.embedding_cluster,
        signature_key="cluster-7",
        status=MemoryNodeStatus.dormant,
    )
    db_session.add_all([finding, shared_node, dormant_node])
    db_session.flush()

    db_session.add_all(
        [
            CorrelationLink(
                memory_node_id=shared_node.id,
                submission_id=owned_submission.id,
                finding_id=finding.id,
                link_reason=LinkReason.shared_rule,
            ),
            CorrelationLink(
                memory_node_id=shared_node.id,
                submission_id=other_submission.id,
                link_reason=LinkReason.embedding_similarity,
                similarity_score=0.91,
            ),
            CorrelationLink(
                memory_node_id=dormant_node.id,
                submission_id=other_submission.id,
                link_reason=LinkReason.embedding_similarity,
                similarity_score=0.82,
            ),
        ]
    )
    db_session.commit()
    return analyst, shared_node, dormant_node


def test_list_memory_nodes_paginates_and_filters(client, db_session):
    analyst, _, _ = _seed_memory_data(db_session)
    app.dependency_overrides[get_current_user] = lambda: analyst

    response = client.get(
        "/api/memory/nodes?signature_type=rule&status=active&page=1&page_size=1"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["page"] == 1
    assert data["page_size"] == 1
    assert data["items"][0]["signature_key"] == "1"


def test_get_memory_node_includes_only_accessible_links(client, db_session):
    analyst, shared_node, _ = _seed_memory_data(db_session)
    app.dependency_overrides[get_current_user] = lambda: analyst

    response = client.get(f"/api/memory/nodes/{shared_node.id}")

    assert response.status_code == 200
    data = response.json()
    assert len(data["links"]) == 1
    link = data["links"][0]
    assert link["link_reason"] == "shared_rule"
    assert link["finding"]["severity"] == "high"
    assert link["submission"]["sanitized_text"] == "owned sanitized text"
    assert "raw_text" not in link["submission"]


def test_analyst_cannot_read_node_linked_only_to_another_user(client, db_session):
    analyst, _, dormant_node = _seed_memory_data(db_session)
    app.dependency_overrides[get_current_user] = lambda: analyst

    response = client.get(f"/api/memory/nodes/{dormant_node.id}")

    assert response.status_code == 404


def test_admin_can_list_global_memory_nodes(client, db_session):
    _, _, _ = _seed_memory_data(db_session)
    admin = User(
        email="memory-admin@test.com",
        hashed_password="unused",
        role=UserRole.admin,
    )
    db_session.add(admin)
    db_session.commit()
    app.dependency_overrides[get_current_user] = lambda: admin

    response = client.get("/api/memory/nodes")

    assert response.status_code == 200
    assert response.json()["total"] == 2


def test_memory_timeline_is_chronological_and_paginated(client, db_session):
    analyst, shared_node, _ = _seed_memory_data(db_session)
    app.dependency_overrides[get_current_user] = lambda: analyst

    for day in (3, 1, 2):
        submission = RawSubmission(
            user_id=analyst.id,
            raw_text=f"timeline submission {day}",
            sanitized_text=f"timeline submission {day}",
        )
        db_session.add(submission)
        db_session.flush()
        db_session.add(
            CorrelationLink(
                memory_node_id=shared_node.id,
                submission_id=submission.id,
                linked_at=datetime(2026, 3, day, tzinfo=timezone.utc),
                link_reason=LinkReason.shared_rule,
            )
        )
    db_session.commit()

    first_page = client.get(
        f"/api/memory/nodes/{shared_node.id}/timeline?page=1&page_size=2"
    )
    second_page = client.get(
        f"/api/memory/nodes/{shared_node.id}/timeline?page=2&page_size=2"
    )

    assert first_page.status_code == 200
    first_data = first_page.json()
    second_data = second_page.json()
    assert first_data["total"] == 4
    assert [item["linked_at"] for item in first_data["items"]] == sorted(
        item["linked_at"] for item in first_data["items"]
    )
    assert len(first_data["items"]) == 2
    assert len(second_data["items"]) == 2
    assert first_data["items"][-1]["linked_at"] < second_data["items"][0]["linked_at"]
