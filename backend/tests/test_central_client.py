"""Tests for optional org-local connectivity to the central registry."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.central_client import (
    CentralClient,
    CentralClientConfigurationError,
    CentralUnavailableError,
)
from app.core.config import Settings, settings
from app.main import app as local_app


def test_central_client_sends_registered_key_as_bearer_token():
    def handle(request):
        assert request.url.path == "/api/central/orgs/me"
        assert request.headers["Authorization"] == "Bearer registered-secret"
        return httpx.Response(
            200,
            json={"id": 1, "name": "Demo Org", "status": "active"},
        )

    with CentralClient(
        "https://central.example.org",
        "registered-secret",
        transport=httpx.MockTransport(handle),
    ) as central:
        assert central.get_org_info()["name"] == "Demo Org"


def test_central_client_posts_anonymized_intel_payload():
    expected_payload = {
        "sanitized_text": "anonymized activity",
        "rule_categories": ["credential exposure"],
        "mitre_technique_ids": ["T1552.001"],
        "severity": ["high"],
        "embedding": None,
    }

    def handle(request):
        assert request.method == "POST"
        assert request.url.path == "/api/central/intel/submit"
        assert request.headers["Authorization"] == "Bearer registered-secret"
        assert json.loads(request.read()) == expected_payload
        return httpx.Response(201, json={"id": 5, "duplicate": False})

    with CentralClient(
        "https://central.example.org",
        "registered-secret",
        transport=httpx.MockTransport(handle),
    ) as central:
        assert central.submit_intel(expected_payload) == {
            "id": 5,
            "duplicate": False,
        }


def test_central_client_search_sends_embedding_and_top_k():
    query = {"embedding": [0.1, 0.2], "top_k": 4}

    def handle(request):
        assert request.method == "POST"
        assert request.url.path == "/api/central/intel/search"
        assert request.headers["Authorization"] == "Bearer registered-secret"
        assert json.loads(request.read()) == query
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "sanitized_text": "anonymized",
                        "mitre_technique_ids": ["T1059"],
                        "severity": ["medium"],
                        "similarity_score": 0.91,
                    }
                ],
                "total_found": 1,
            },
        )

    with CentralClient(
        "https://central.example.org",
        "registered-secret",
        transport=httpx.MockTransport(handle),
    ) as central:
        result = central.search_intel(query["embedding"], top_k=query["top_k"])
    assert result["total_found"] == 1
    assert "source_org_id" not in str(result)


def test_central_client_uses_admin_token_for_aggregate_statistics(monkeypatch):
    monkeypatch.setattr(settings, "CENTRAL_ADMIN_TOKEN", "central-admin-test")

    def handle(request):
        assert request.method == "GET"
        assert request.url.path == "/api/central/intel/stats"
        assert request.headers["Authorization"] == "Bearer registered-secret"
        assert request.headers["X-Central-Admin-Token"] == "central-admin-test"
        return httpx.Response(200, json={"total": 0, "by_technique": [], "by_severity": []})

    with CentralClient(
        "https://central.example.org",
        "registered-secret",
        transport=httpx.MockTransport(handle),
    ) as central:
        assert central.get_intel_stats()["total"] == 0


def test_central_client_retries_then_opens_circuit(monkeypatch):
    attempts = []
    sleeps = []
    now = [100.0]

    def fail(request):
        attempts.append(request)
        raise httpx.ConnectError("central unavailable", request=request)

    monkeypatch.setattr(settings, "CENTRAL_MAX_RETRIES", 2)
    monkeypatch.setattr(settings, "CENTRAL_CIRCUIT_FAILURE_THRESHOLD", 1)
    monkeypatch.setattr(settings, "CENTRAL_CIRCUIT_COOLDOWN_SECONDS", 20.0)
    with CentralClient(
        "http://central.test",
        "api-key",
        transport=httpx.MockTransport(fail),
        sleep=sleeps.append,
        clock=lambda: now[0],
    ) as central:
        with pytest.raises(CentralUnavailableError) as failure:
            central.get_org_info()
        assert failure.value.attempts == 3
        assert len(sleeps) == 2

        with pytest.raises(CentralUnavailableError) as circuit:
            central.get_org_info()
        assert circuit.value.attempts == 0
        assert circuit.value.retry_after_seconds == 20
        assert len(attempts) == 3


def test_non_development_configuration_rejects_plain_http(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    with pytest.raises(CentralClientConfigurationError, match="HTTPS"):
        CentralClient("http://central.example.org", "registered-secret")
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(
            ENVIRONMENT="production",
            CENTRAL_SERVER_URL="http://central.example.org",
        )


def test_local_health_remains_available_when_central_is_unreachable():
    def fail(request):
        raise httpx.ConnectError("central unavailable", request=request)

    with CentralClient(
        "http://central.test",
        "api-key",
        transport=httpx.MockTransport(fail),
        sleep=lambda _: None,
    ) as central:
        with pytest.raises(CentralUnavailableError):
            central.get_org_info()

    with TestClient(local_app) as local:
        assert local.get("/api/health").status_code == 200
