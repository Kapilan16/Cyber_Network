from __future__ import annotations

import httpx
import pytest
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker

from app.enrichment.client import (
    EnrichmentError,
    EnrichmentResponse,
    MissingAPIKeyError,
    ProviderRateLimiter,
    ThreatIntelClient,
)
from app.enrichment.iocs import extract_iocs
from app.enrichment.tasks import process_enrichment_results
from app.models.enrichment import (
    EnrichmentResult,
    EnrichmentSource,
    EnrichmentStatus,
    IOCType,
)
from app.models.raw_submission import RawSubmission, SourceType
from app.models.risk_score import RiskScore


def _auth_token(client) -> str:
    credentials = {
        "email": "enrichment-analyst@example.com",
        "password": "P@ssw0rd!!",
    }
    registered = client.post("/api/auth/register", json=credentials)
    assert registered.status_code == 201
    response = client.post("/api/auth/login", json=credentials)
    assert response.status_code == 200
    return response.json()["access_token"]


def test_extract_iocs_reuses_seed_patterns_and_deduplicates_values():
    md5 = "a" * 32
    sha1 = "b" * 40
    sha256 = "c" * 64
    results = extract_iocs(
        f"Bad hosts 8.8.8.8, 10.1.2.3, 2001:4860:4860::8888 and fd00::1; "
        f"domain EVIL.Example.com and node.internal. "
        f"hashes {md5}, {sha1}, {sha256}; duplicate 8.8.8.8"
    )

    assert {(item.ioc_type, item.ioc_value) for item in results} == {
        ("ip", "8.8.8.8"),
        ("ip", "10.1.2.3"),
        ("ip", "2001:4860:4860::8888"),
        ("ip", "fd00::1"),
        ("domain", "evil.example.com"),
        ("domain", "node.internal"),
        ("hash", md5),
        ("hash", sha1),
        ("hash", sha256),
    }
    assert not next(item for item in results if item.ioc_value == "10.1.2.3").externally_queryable
    assert not next(item for item in results if item.ioc_value == "fd00::1").externally_queryable
    assert not next(item for item in results if item.ioc_value == "node.internal").externally_queryable
    assert next(item for item in results if item.ioc_value == "8.8.8.8").externally_queryable


def test_virustotal_client_returns_trimmed_summary_over_https():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.scheme == "https"
        assert request.url.host == "www.virustotal.com"
        assert request.headers["x-apikey"] == "vt-test"
        assert request.url.path.endswith("/ip_addresses/8.8.8.8")
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                            "harmless": 7,
                            "undetected": 10,
                            "extra": "not retained",
                        },
                        "reputation": -3,
                        "last_analysis_date": 123,
                        "full_payload": "not retained",
                    }
                }
            },
        )

    response = ThreatIntelClient(
        virustotal_api_key="vt-test",
        transport=httpx.MockTransport(handler),
        rate_limiter=ProviderRateLimiter({"virustotal": 0, "abuseipdb": 0}),
    ).query("virustotal", "ip", "8.8.8.8")

    assert response.reputation_score == 15
    assert response.raw_response_summary == {
        "last_analysis_stats": {
            "malicious": 2,
            "suspicious": 1,
            "harmless": 7,
            "undetected": 10,
        },
        "reputation": -3,
        "last_analysis_date": 123,
    }


def test_abuseipdb_client_returns_score_and_rejects_non_ip():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.scheme == "https"
        assert request.url.host == "api.abuseipdb.com"
        assert request.url.params["ipAddress"] == "1.1.1.1"
        assert request.headers["Key"] == "abuse-test"
        return httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 42,
                    "totalReports": 8,
                    "numDistinctUsers": 4,
                    "countryCode": "US",
                    "isp": "not retained",
                }
            },
        )

    client = ThreatIntelClient(
        abuseipdb_api_key="abuse-test",
        transport=httpx.MockTransport(handler),
        rate_limiter=ProviderRateLimiter({"virustotal": 0, "abuseipdb": 0}),
    )
    result = client.query("abuseipdb", "ip", "1.1.1.1")
    assert result.reputation_score == 42
    assert "isp" not in result.raw_response_summary
    with pytest.raises(EnrichmentError):
        client.query("abuseipdb", "hash", "a" * 32)


def test_missing_key_and_provider_errors_are_explicit():
    limiter = ProviderRateLimiter({"virustotal": 0, "abuseipdb": 0})
    with pytest.raises(MissingAPIKeyError):
        ThreatIntelClient(rate_limiter=limiter).query(
            "virustotal", "hash", "a" * 32
        )

    client = ThreatIntelClient(
        virustotal_api_key="key",
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(503, json={"error": "unavailable"})
        ),
        rate_limiter=limiter,
        sleep=lambda _delay: None,
    )
    with pytest.raises(EnrichmentError, match="HTTP 503"):
        client.query("virustotal", "hash", "a" * 32)


def test_429_is_retried_and_requests_are_throttled():
    now = [0.0]
    sleeps: list[float] = []

    def sleep(delay: float) -> None:
        sleeps.append(delay)
        now[0] += delay

    limiter = ProviderRateLimiter(
        {"virustotal": 10, "abuseipdb": 0},
        sleep=sleep,
        clock=lambda: now[0],
    )
    statuses = iter([429, 200])

    def handler(_request: httpx.Request) -> httpx.Response:
        status = next(statuses)
        if status == 429:
            return httpx.Response(429, headers={"Retry-After": "3"})
        return httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {}}}},
        )

    client = ThreatIntelClient(
        virustotal_api_key="key",
        transport=httpx.MockTransport(handler),
        rate_limiter=limiter,
        sleep=sleep,
    )
    client.query("virustotal", "hash", "a" * 32)
    assert 3.0 in sleeps
    assert any(delay == 7.0 for delay in sleeps)


def test_background_queue_marks_provider_failures_and_private_ips_without_blocking(
    db_session: Session,
):
    submission = RawSubmission(
        user_id=1,
        raw_text="report",
        source_type=SourceType.alert,
        sanitized_text="10.0.0.1 8.8.8.8",
    )
    db_session.add(submission)
    db_session.commit()
    db_session.refresh(submission)
    first = EnrichmentResult(
        submission_id=submission.id,
        ioc_type=IOCType.ip,
        ioc_value="10.0.0.1",
        source=EnrichmentSource.virustotal,
        status=EnrichmentStatus.pending,
    )
    second = EnrichmentResult(
        submission_id=submission.id,
        ioc_type=IOCType.ip,
        ioc_value="8.8.8.8",
        source=EnrichmentSource.virustotal,
        status=EnrichmentStatus.pending,
    )
    db_session.add_all([first, second])
    db_session.commit()
    first_id, second_id = first.id, second.id
    calls: list[str] = []

    class Client:
        def query(self, _source, _ioc_type, value):
            calls.append(value)
            raise MissingAPIKeyError("key not set")

    process_enrichment_results(
        [first_id, second_id],
        session_factory=sessionmaker(bind=db_session.get_bind()),
        client=Client(),
    )
    db_session.expire_all()
    first = db_session.get(EnrichmentResult, first_id)
    second = db_session.get(EnrichmentResult, second_id)
    stored_submission = db_session.get(RawSubmission, submission.id)

    assert calls == ["8.8.8.8"]
    assert first.status == EnrichmentStatus.failed
    assert "not sent" in first.raw_response_summary["error"]
    assert second.status == EnrichmentStatus.failed
    assert second.raw_response_summary == {"error": "key not set"}
    assert stored_submission.sanitized_text == "10.0.0.1 8.8.8.8"


def test_background_queue_persists_successful_trimmed_provider_result(
    db_session: Session,
):
    submission = RawSubmission(
        user_id=1,
        raw_text="report",
        source_type=SourceType.alert,
        sanitized_text="8.8.8.8",
    )
    db_session.add(submission)
    db_session.commit()
    db_session.refresh(submission)
    result = EnrichmentResult(
        submission_id=submission.id,
        ioc_type=IOCType.ip,
        ioc_value="8.8.8.8",
        source=EnrichmentSource.virustotal,
        status=EnrichmentStatus.pending,
    )
    db_session.add(result)
    db_session.commit()
    result_id = result.id

    class Client:
        def query(self, source, ioc_type, ioc_value):
            assert (source, ioc_type, ioc_value) == (
                "virustotal",
                "ip",
                "8.8.8.8",
            )
            return EnrichmentResponse(
                reputation_score=25,
                raw_response_summary={"malicious": 1, "harmless": 3},
            )

    process_enrichment_results(
        [result_id],
        session_factory=sessionmaker(bind=db_session.get_bind()),
        client=Client(),
    )
    db_session.expire_all()
    saved = db_session.get(EnrichmentResult, result_id)
    assert saved.status == EnrichmentStatus.complete
    assert saved.reputation_score == 25
    assert saved.raw_response_summary == {"malicious": 1, "harmless": 3}
    assert saved.queried_at is not None
    risk = db_session.query(RiskScore).filter_by(submission_id=submission.id).one()
    assert risk.components["enrichment_signal"] == 25
    assert risk.components["enrichment_contribution"] == 7.5


def test_submission_processing_never_calls_threat_intel_and_enrichment_is_queued(
    client,
):
    from unittest.mock import patch

    token = _auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    with patch(
        "app.enrichment.client.ThreatIntelClient.query",
        side_effect=AssertionError("submission intake must not query external providers"),
    ) as query:
        created = client.post(
            "/api/submissions",
            headers=headers,
            json={
                "raw_text": "Suspicious connection to 8.8.8.8 and threat.example.com",
                "source_type": "alert",
            },
        )
    assert created.status_code == 201
    query.assert_not_called()

    with patch(
        "app.api.v1.endpoints.submissions.process_enrichment_results"
    ) as queued:
        response = client.post(
            f"/api/submissions/{created.json()['id']}/enrich",
            headers=headers,
        )
    assert response.status_code == 202
    payload = response.json()
    assert payload["iocs_detected"] == 2
    assert payload["enrichments_queued"] == 3
    queued.assert_called_once()

    results = client.get(
        f"/api/submissions/{created.json()['id']}/enrichment",
        headers=headers,
    )
    assert results.status_code == 200
    assert len(results.json()) == 3
    assert {row["status"] for row in results.json()} == {"pending"}
