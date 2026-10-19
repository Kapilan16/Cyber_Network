"""Unit tests for long-term submission correlation."""
from datetime import datetime, timezone

from app.correlation import engine
from app.api.v1.endpoints import submissions as submission_endpoints
from app.models.memory import CorrelationLink, LinkReason, MemoryNode, SignatureType
from app.models.raw_submission import RawSubmission
from app.models.rule import Finding, Rule, Severity
from app.models.user import User


def _submission_with_finding(db_session, *, mitre_technique_id=None, embedding=None):
    user = User(email="correlation@test.com", hashed_password="unused")
    db_session.add(user)
    db_session.flush()
    rule = Rule(
        name=f"correlation-rule-{mitre_technique_id or 'plain'}",
        condition_json={},
        mitre_technique_id=mitre_technique_id,
    )
    submission = RawSubmission(
        user_id=user.id,
        raw_text="sample",
        sanitized_text="sample",
        embedding=embedding,
        submitted_at=datetime.now(timezone.utc),
    )
    db_session.add_all([rule, submission])
    db_session.flush()
    finding = Finding(
        submission_id=submission.id,
        rule_id=rule.id,
        severity=Severity.medium,
    )
    db_session.add(finding)
    db_session.flush()
    return submission, finding


def test_correlates_finding_to_technique_and_rule(db_session, monkeypatch):
    monkeypatch.setattr(engine, "find_similar_submissions", lambda *args, **kwargs: [])
    submission, finding = _submission_with_finding(
        db_session, mitre_technique_id="T1059.001"
    )

    links = engine.correlate_submission(submission, [finding], db_session)

    assert {link.link_reason for link in links} == {
        LinkReason.shared_technique,
        LinkReason.shared_rule,
    }
    assert all(link.finding_id == finding.id for link in links)
    nodes = db_session.query(MemoryNode).all()
    assert {(node.signature_type, node.signature_key) for node in nodes} == {
        (SignatureType.mitre_technique, "T1059.001"),
        (SignatureType.rule, str(finding.rule_id)),
    }


def test_reuses_rule_node_and_increments_occurrence(db_session, monkeypatch):
    monkeypatch.setattr(engine, "find_similar_submissions", lambda *args, **kwargs: [])
    submission, finding = _submission_with_finding(db_session)
    existing = MemoryNode(
        signature_type=SignatureType.rule,
        signature_key=str(finding.rule_id),
        occurrence_count=4,
    )
    db_session.add(existing)
    db_session.flush()

    links = engine.correlate_submission(submission, [finding], db_session)

    assert len(links) == 1
    assert links[0].memory_node is existing
    assert existing.occurrence_count == 5


def test_correlates_embedding_only_above_configured_threshold(
    db_session, monkeypatch
):
    current, finding = _submission_with_finding(db_session, embedding=[0.1])
    prior = RawSubmission(
        user_id=current.user_id,
        raw_text="prior",
        sanitized_text="prior",
        embedding=[0.1],
    )
    db_session.add(prior)
    db_session.flush()
    monkeypatch.setattr(engine.settings, "CORRELATION_SIMILARITY_THRESHOLD", 0.85)
    monkeypatch.setattr(
        engine,
        "find_similar_submissions",
        lambda *args, **kwargs: [(prior, 0.91), (prior, 0.84)],
    )

    links = engine.correlate_submission(current, [], db_session)

    assert len(links) == 1
    assert links[0].link_reason == LinkReason.embedding_similarity
    assert links[0].similarity_score == 0.91
    assert links[0].finding_id is None
    assert links[0].memory_node.signature_type == SignatureType.embedding_cluster
    assert links[0].memory_node.signature_key == f"submission-{prior.id}"


def test_returns_no_links_without_findings_or_embedding(db_session, monkeypatch):
    monkeypatch.setattr(engine, "find_similar_submissions", lambda *args, **kwargs: [])
    submission, _ = _submission_with_finding(db_session)

    links = engine.correlate_submission(submission, [], db_session)

    assert links == []
    assert db_session.query(CorrelationLink).count() == 0


def test_submission_schedules_correlation_after_ingestion(client, monkeypatch):
    scheduled_ids = []

    async def record_submission(submission_id):
        scheduled_ids.append(submission_id)

    monkeypatch.setattr(
        submission_endpoints,
        "correlate_submission_background",
        record_submission,
    )
    credentials = {"email": "correlation-api@test.com", "password": "P@ssword123!"}
    assert client.post("/api/auth/register", json=credentials).status_code == 201
    token = client.post("/api/auth/login", json=credentials).json()["access_token"]

    response = client.post(
        "/api/submissions",
        json={"raw_text": "new submission for correlation"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 201
    assert scheduled_ids == [response.json()["id"]]
