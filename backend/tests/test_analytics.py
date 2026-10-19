from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import sessionmaker

from app.models.early_warning import EarlyWarning
from app.models.enrichment import (
    EnrichmentResult,
    EnrichmentSource,
    EnrichmentStatus,
    IOCType,
)
from app.models.mitre_technique import MitreTechnique
from app.models.organization import Organization
from app.models.raw_submission import RawSubmission, SourceType
from app.models.risk_score import RiskBand, RiskScore
from app.models.rule import Finding, Rule, Severity
from app.models.user import User
from app.analytics.warnings import scan_early_warnings
from app.core.config import settings
from app.enrichment.tasks import process_enrichment_results
from app.enrichment.client import EnrichmentResponse
from app.recommendations.client import RecommendationContent


def test_analytics_aggregates_org_signals_and_network_comparison(
    client,
    db_session,
    monkeypatch,
):
    credentials = {
        "email": "analytics-analyst@example.com",
        "password": "P@ssw0rd!!",
    }
    db_session.add(Organization(id=1, name="Analytics test org"))
    db_session.commit()
    assert client.post("/api/auth/register", json=credentials).status_code == 201
    token = client.post("/api/auth/login", json=credentials).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    user = db_session.query(User).filter_by(email=credentials["email"]).one()
    organization = db_session.get(Organization, user.org_id)
    organization.share_with_network = True

    db_session.add(
        MitreTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic="Execution",
        )
    )
    rule = Rule(
        name="Analytics test rule",
        description="analytics fixture",
        condition_json={"op": "contains", "value": "test"},
        severity=Severity.high,
        mitre_technique_id="T1059",
        is_active=True,
    )
    db_session.add(rule)
    db_session.commit()
    db_session.refresh(rule)

    now = datetime.now(timezone.utc)
    submissions = []
    for index, band in enumerate(
        [RiskBand.high, RiskBand.high, RiskBand.critical]
    ):
        submission = RawSubmission(
            user_id=user.id,
            raw_text=f"test event {index}",
            sanitized_text=f"test event {index}",
            source_type=SourceType.alert,
            submitted_at=now - timedelta(days=index),
        )
        db_session.add(submission)
        db_session.flush()
        db_session.add_all(
            [
                Finding(
                    submission_id=submission.id,
                    rule_id=rule.id,
                    severity=Severity.high,
                ),
                RiskScore(
                    submission_id=submission.id,
                    score=80 if band == RiskBand.critical else 60,
                    band=band,
                    components={},
                ),
            ]
        )
        submissions.append(submission)
    db_session.flush()
    db_session.add_all(
        [
            EnrichmentResult(
                submission_id=submissions[0].id,
                ioc_type=IOCType.ip,
                ioc_value="203.0.113.9",
                source=EnrichmentSource.virustotal,
                reputation_score=0,
                status=EnrichmentStatus.complete,
            ),
            EnrichmentResult(
                submission_id=submissions[1].id,
                ioc_type=IOCType.domain,
                ioc_value="malicious.example",
                source=EnrichmentSource.virustotal,
                reputation_score=5,
                status=EnrichmentStatus.complete,
            ),
        ]
    )
    db_session.commit()
    warning_rows = scan_early_warnings(
        db_session,
        now=now,
        window_hours=24 * 7,
        threshold=3,
    )
    assert len(warning_rows) == 2  # shared tactic plus shared technique

    class CentralStats:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get_intel_stats(self):
            return {
                "total": 12,
                "by_technique": [{"technique_id": "T1059", "count": 8}],
                "by_severity": [],
            }

    monkeypatch.setattr(settings, "CENTRAL_SERVER_URL", "http://central.test")
    monkeypatch.setattr(settings, "CENTRAL_API_KEY", "test-api-key")
    monkeypatch.setattr(
        "app.api.v1.endpoints.analytics.CentralClient",
        CentralStats,
    )
    response = client.get("/api/analytics/overview", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert {
        item["name"]: item["count"]
        for item in body["risk_band_distribution"]
    } == {"low": 0, "medium": 0, "high": 2, "critical": 1}
    assert body["top_mitre_tactics"]["last_7_days"] == [
        {"name": "Execution", "count": 3}
    ]
    assert body["top_mitre_tactics"]["last_30_days"] == [
        {"name": "Execution", "count": 3}
    ]
    assert body["enriched_iocs"] == 2
    assert body["non_clean_iocs"] == 1
    assert body["enrichment_hit_rate"] == 50
    assert len(body["average_risk_score_trend"]) == 30
    assert len(body["active_warnings"]) == 2
    assert body["network_context"]["available"] is True
    assert body["network_context"]["central_total"] == 12
    assert body["network_context"]["by_tactic"] == [
        {"tactic": "Execution", "local_count": 3, "network_count": 8}
    ]


def test_early_warning_scanner_only_warns_for_high_risk_in_window(
    db_session,
):
    organization = Organization(name="Warning test")
    db_session.add(organization)
    db_session.flush()
    user = User(
        org_id=organization.id,
        email="warning-test@example.com",
        hashed_password="unused",
    )
    technique = MitreTechnique(
        id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
    )
    rule = Rule(
        name="Warning threshold rule",
        condition_json={},
        severity=Severity.high,
        mitre_technique_id=technique.id,
    )
    db_session.add_all([user, technique, rule])
    db_session.flush()
    now = datetime.now(timezone.utc)
    for index, (band, age) in enumerate(
        [
            (RiskBand.high, timedelta(hours=1)),
            (RiskBand.critical, timedelta(hours=2)),
            (RiskBand.medium, timedelta(minutes=30)),
            (RiskBand.high, timedelta(hours=30)),
        ]
    ):
        submission = RawSubmission(
            user_id=user.id,
            raw_text=f"event {index}",
            sanitized_text=f"event {index}",
            source_type=SourceType.alert,
            submitted_at=now - age,
        )
        db_session.add(submission)
        db_session.flush()
        db_session.add_all(
            [
                Finding(
                    submission_id=submission.id,
                    rule_id=rule.id,
                    severity=Severity.high,
                ),
                RiskScore(
                    submission_id=submission.id,
                    score=80,
                    band=band,
                    components={},
                ),
            ]
        )
    db_session.commit()

    warnings = scan_early_warnings(
        db_session,
        now=now,
        window_hours=24,
        threshold=2,
    )

    assert len(warnings) == 2
    assert all(len(warning.submission_ids) == 2 for warning in warnings)
    assert db_session.query(EarlyWarning).count() == 2


def test_stage3_submission_to_analytics_smoke_flow(
    client,
    db_session,
    monkeypatch,
):
    credentials = {
        "email": "stage3-smoke@example.com",
        "password": "P@ssw0rd!!",
    }
    db_session.add(Organization(id=1, name="Stage 3 smoke org"))
    db_session.commit()
    assert client.post("/api/auth/register", json=credentials).status_code == 201
    token = client.post("/api/auth/login", json=credentials).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    rule = Rule(
        name="Stage 3 smoke rule",
        description="Detect the smoke test indicator.",
        condition_json={"op": "contains", "value": "stage3-suspicious"},
        severity=Severity.critical,
        mitre_technique_id="T1059",
        is_active=True,
    )
    db_session.add(
        MitreTechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic="Execution",
        )
    )
    db_session.add(rule)
    db_session.commit()

    monkeypatch.setattr(settings, "RISK_WEIGHT_RULE_SEVERITY", 0.0)
    monkeypatch.setattr(settings, "RISK_WEIGHT_RECURRENCE", 0.0)
    monkeypatch.setattr(settings, "RISK_WEIGHT_ENRICHMENT", 1.0)
    monkeypatch.setattr(settings, "WARNING_THRESHOLD", 3)
    monkeypatch.setattr(settings, "WARNING_WINDOW_HOURS", 24)
    enrichment_session_factory = sessionmaker(
        bind=db_session.get_bind(),
        autoflush=False,
        autocommit=False,
    )

    class MockThreatIntelClient:
        def query(self, source, ioc_type, ioc_value):
            return EnrichmentResponse(
                reputation_score=100 if source == "virustotal" else 0,
                raw_response_summary={"mocked": True},
            )

    class MockRecommendationClient:
        def generate(self, _context):
            return RecommendationContent(
                recommendation_text="Review the suspicious activity and validate scope.",
                suggested_actions=[
                    "Confirm the affected endpoint.",
                    "Review related event logs.",
                    "Escalate confirmed malicious behavior.",
                ],
                confidence=0.8,
            )

    monkeypatch.setattr(
        "app.api.v1.endpoints.submissions.process_enrichment_results",
        lambda ids: process_enrichment_results(
            ids,
            session_factory=enrichment_session_factory,
            client=MockThreatIntelClient(),
        ),
    )
    monkeypatch.setattr(
        "app.recommendations.service.RecommendationClient",
        MockRecommendationClient,
    )

    submission_ids = []
    for index in range(3):
        submitted = client.post(
            "/api/submissions",
            headers=headers,
            json={
                "raw_text": (
                    f"stage3-suspicious event {index}; "
                    "contact 8.8.8.8 and threat.example.com"
                ),
                "source_type": "alert",
            },
        )
        assert submitted.status_code == 201, submitted.text
        created = submitted.json()
        submission_ids.append(created["id"])
        findings = client.get(
            f"/api/submissions/{created['id']}/findings",
            headers=headers,
        )
        assert findings.status_code == 200
        assert len(findings.json()) == 1
        enrichment = client.post(
            f"/api/submissions/{created['id']}/enrich",
            headers=headers,
        )
        assert enrichment.status_code == 202
        assert enrichment.json()["enrichments_queued"] > 0
        saved_enrichment = client.get(
            f"/api/submissions/{created['id']}/enrichment",
            headers=headers,
        )
        assert saved_enrichment.status_code == 200
        assert {item["status"] for item in saved_enrichment.json()} == {"complete"}

    recommendations = client.post(
        f"/api/submissions/{submission_ids[0]}/recommend",
        headers=headers,
    )
    assert recommendations.status_code == 202
    saved_recommendation = client.get(
        f"/api/submissions/{submission_ids[0]}/recommendation",
        headers=headers,
    )
    assert saved_recommendation.status_code == 200
    assert saved_recommendation.json()["status"] == "complete"

    overview = client.get("/api/analytics/overview", headers=headers)
    assert overview.status_code == 200
    result = overview.json()
    assert next(
        item["count"]
        for item in result["risk_band_distribution"]
        if item["name"] == "critical"
    ) == 3
    assert result["top_mitre_tactics"]["last_7_days"] == [
        {"name": "Execution", "count": 3}
    ]
    assert result["enrichment_hit_rate"] == 100
    assert any(
        len(warning["submission_ids"]) == 3
        for warning in result["active_warnings"]
    )
