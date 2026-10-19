from __future__ import annotations

from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from app.central_client import CentralUnavailableError
from app.core.config import settings
from app.models.raw_submission import RawSubmission, SourceType
from app.models.enrichment import EnrichmentResult, EnrichmentSource, EnrichmentStatus, IOCType
from app.models.risk_score import RiskBand
from app.models.rule import Rule, Severity
from app.risk.scoring import calculate_risk_score
from app.risk.service import compute_submission_risk_score


def test_scoring_normalizes_across_weight_combinations():
    balanced = calculate_risk_score(
        ["high"],
        2,
        60,
        weights={"rule_severity": 0.4, "recurrence": 0.3, "enrichment": 0.3},
    )
    severity_only = calculate_risk_score(
        ["high", "low"],
        0,
        0,
        weights={"rule_severity": 1, "recurrence": 0, "enrichment": 0},
    )
    enrichment_only = calculate_risk_score(
        [],
        0,
        80,
        weights={"rule_severity": 0, "recurrence": 0, "enrichment": 5},
    )

    assert balanced.score == 60
    assert balanced.components["rule_severity_contribution"] == 30
    assert balanced.components["recurrence_contribution"] == 12
    assert balanced.components["enrichment_contribution"] == 18
    assert severity_only.score == 75
    assert enrichment_only.score == 80


def test_scoring_has_documented_risk_band_boundaries():
    weights = {"rule_severity": 0, "recurrence": 0, "enrichment": 1}
    expected = {
        0: RiskBand.low,
        24: RiskBand.low,
        25: RiskBand.medium,
        49: RiskBand.medium,
        50: RiskBand.high,
        74: RiskBand.high,
        75: RiskBand.critical,
        100: RiskBand.critical,
    }
    for score, band in expected.items():
        assert calculate_risk_score([], 0, score, weights=weights).band == band


def test_network_unavailable_keeps_local_recurrence_in_score(
    db_session: Session,
    monkeypatch,
):
    now = datetime.now(timezone.utc)
    previous = RawSubmission(
        user_id=1,
        raw_text="previous",
        source_type=SourceType.alert,
        sanitized_text="previous",
        embedding=[1.0, 0.0, 0.0],
        submitted_at=now - timedelta(minutes=1),
    )
    current = RawSubmission(
        user_id=1,
        raw_text="current",
        source_type=SourceType.alert,
        sanitized_text="current",
        embedding=[1.0, 0.0, 0.0],
        submitted_at=now,
    )
    db_session.add_all([previous, current])
    db_session.commit()
    db_session.refresh(current)

    class ColdIndex:
        available = False
        count = 0

    monkeypatch.setattr("app.risk.service.get_faiss_index", lambda: ColdIndex())
    monkeypatch.setattr(settings, "CENTRAL_SERVER_URL", "https://central.example.test")
    monkeypatch.setattr(settings, "CENTRAL_API_KEY", "configured")
    monkeypatch.setattr(
        "app.risk.service.CentralClient",
        lambda: (_ for _ in ()).throw(CentralUnavailableError("offline", attempts=1)),
    )

    score = compute_submission_risk_score(db_session, current.id)
    assert score is not None
    assert score.components["local_recurrence_count"] == 1
    assert score.components["network_recurrence_count"] == 0
    assert score.components["recurrence_contribution"] == 6


def test_risk_score_waits_until_enrichment_finishes(db_session: Session):
    submission = RawSubmission(
        user_id=1,
        raw_text="indicator",
        source_type=SourceType.alert,
        sanitized_text="indicator",
    )
    db_session.add(submission)
    db_session.commit()
    db_session.refresh(submission)
    db_session.add(
        EnrichmentResult(
            submission_id=submission.id,
            ioc_type=IOCType.domain,
            ioc_value="threat.example.com",
            source=EnrichmentSource.virustotal,
            status=EnrichmentStatus.pending,
        )
    )
    db_session.commit()

    assert compute_submission_risk_score(db_session, submission.id) is None


def test_submission_scoring_refreshes_after_rule_evaluation_and_appears_in_list(client, db_session):
    credentials = {"email": "risk-analyst@example.com", "password": "P@ssw0rd!!"}
    assert client.post("/api/auth/register", json=credentials).status_code == 201
    token = client.post("/api/auth/login", json=credentials).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    db_session.add(
        Rule(
            name="Risk score test rule",
            description="Test rule that indicates a high-risk event.",
            condition_json={"op": "contains", "value": "critical indicator"},
            severity=Severity.high,
            is_active=True,
        )
    )
    db_session.commit()

    created = client.post(
        "/api/submissions",
        headers=headers,
        json={
            "raw_text": "critical indicator",
            "source_type": "alert",
        },
    )
    assert created.status_code == 201
    submission_id = created.json()["id"]
    risk_url = f"/api/submissions/{submission_id}/risk-score"
    initial = client.get(risk_url, headers=headers)
    assert initial.status_code == 200
    assert initial.json()["band"] == "medium"

    evaluated = client.post(
        f"/api/submissions/{submission_id}/evaluate",
        headers=headers,
    )
    assert evaluated.status_code == 200
    refreshed = client.get(risk_url, headers=headers)
    assert refreshed.status_code == 200
    assert refreshed.json()["components"]["rule_severity_signal"] == 75
    listed = client.get("/api/submissions", headers=headers)
    row = next(item for item in listed.json()["items"] if item["id"] == submission_id)
    assert row["risk_band"] == "medium"
    assert row["risk_score"] == refreshed.json()["score"]
