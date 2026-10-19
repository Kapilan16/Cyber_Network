from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models.raw_submission import RawSubmission, SourceType
from app.models.recommendation import AiRecommendation, RecommendationStatus
from app.recommendations.client import (
    RecommendationClient,
    RecommendationContent,
    RecommendationGenerationError,
)
from app.recommendations.service import generate_recommendation_background


def _valid_content() -> dict:
    return {
        "recommendation_text": "Review the alert and validate the observed activity.",
        "suggested_actions": [
            "Confirm the affected asset with its owner.",
            "Review relevant authentication and endpoint logs.",
            "Escalate confirmed malicious activity through incident response.",
        ],
        "confidence": 0.82,
    }


def _auth_headers(client) -> dict[str, str]:
    credentials = {
        "email": "recommendation-analyst@example.com",
        "password": "P@ssw0rd!!",
    }
    assert client.post("/api/auth/register", json=credentials).status_code == 201
    token = client.post("/api/auth/login", json=credentials).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_recommendation_client_sends_https_and_validates_structured_json():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.scheme == "https"
        assert request.headers["Authorization"] == "Bearer test-key"
        body = json.loads(request.content)
        assert body["response_format"]["type"] == "json_schema"
        assert "sanitized_submission_text" in json.loads(
            body["messages"][1]["content"]
        )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": json.dumps(_valid_content())}}
                ]
            },
        )

    client = RecommendationClient(
        api_key="test-key",
        api_url="https://ai.example.test/v1/chat/completions",
        model="test-model",
        transport=httpx.MockTransport(handler),
    )
    result = client.generate({"sanitized_submission_text": "sanitized evidence"})
    assert result.recommendation_text.startswith("Review the alert")
    assert len(result.suggested_actions) == 3
    assert result.confidence == 0.82


@pytest.mark.parametrize(
    "content",
    [
        {"recommendation_text": "summary", "suggested_actions": ["one"], "confidence": None},
        {**_valid_content(), "unrecognized": "must be rejected"},
        {**_valid_content(), "confidence": 1.1},
        {**_valid_content(), "suggested_actions": ["", "two", "three"]},
    ],
)
def test_recommendation_content_rejects_malformed_or_out_of_schema_values(content):
    with pytest.raises(ValidationError):
        RecommendationContent.model_validate(content)


def test_recommendation_client_rejects_malformed_provider_json():
    client = RecommendationClient(
        api_key="test-key",
        api_url="https://ai.example.test/v1/chat/completions",
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={"choices": [{"message": {"content": '{"summary":"bad"}'}}]},
            )
        ),
    )
    with pytest.raises(RecommendationGenerationError):
        client.generate({"sanitized_submission_text": "evidence"})


def test_recommendation_api_caches_and_only_regenerates_explicitly(
    client,
    db_session,
    monkeypatch,
):
    headers = _auth_headers(client)
    submission = RawSubmission(
        user_id=1,
        raw_text="raw alert",
        sanitized_text="sanitized suspicious activity",
        source_type=SourceType.alert,
    )
    db_session.add(submission)
    db_session.commit()
    db_session.refresh(submission)
    queued: list[int] = []
    monkeypatch.setattr(
        "app.api.v1.endpoints.submissions.generate_recommendation_background",
        lambda recommendation_id, **_kwargs: queued.append(recommendation_id),
    )

    first = client.post(
        f"/api/submissions/{submission.id}/recommend",
        headers=headers,
    )
    assert first.status_code == 202
    assert first.json()["status"] == "pending"
    assert len(queued) == 1

    pending_again = client.post(
        f"/api/submissions/{submission.id}/recommend",
        headers=headers,
    )
    assert pending_again.status_code == 202
    assert len(queued) == 1

    cached = db_session.query(AiRecommendation).one()
    cached.recommendation_text = "Cached recommendation"
    cached.suggested_actions = ["one", "two", "three"]
    cached.status = RecommendationStatus.complete
    db_session.commit()
    cached_response = client.post(
        f"/api/submissions/{submission.id}/recommend",
        headers=headers,
    )
    assert cached_response.status_code == 200
    assert cached_response.json()["recommendation_text"] == "Cached recommendation"
    assert len(queued) == 1

    regenerated = client.post(
        f"/api/submissions/{submission.id}/recommend?regenerate=true",
        headers=headers,
    )
    assert regenerated.status_code == 202
    assert regenerated.json()["status"] == "pending"
    assert len(queued) == 2
    assert client.get(
        f"/api/submissions/{submission.id}/recommendation",
        headers=headers,
    ).status_code == 200


def test_missing_ai_configuration_marks_failed_without_blocking_submission(
    db_session,
    monkeypatch,
):
    submission = RawSubmission(
        user_id=1,
        raw_text="raw alert",
        sanitized_text="sanitized suspicious activity",
        source_type=SourceType.alert,
    )
    db_session.add(submission)
    db_session.commit()
    db_session.refresh(submission)
    recommendation = AiRecommendation(
        submission_id=submission.id,
        status=RecommendationStatus.pending,
    )
    db_session.add(recommendation)
    db_session.commit()
    recommendation_id = recommendation.id
    factory = sessionmaker(
        bind=db_session.get_bind(),
        autoflush=False,
        autocommit=False,
    )
    monkeypatch.setattr(settings, "AI_API_KEY", "")

    generate_recommendation_background(
        recommendation_id,
        session_factory=factory,
    )

    db_session.expire_all()
    stored = db_session.get(AiRecommendation, recommendation_id)
    assert stored is not None
    assert stored.status == RecommendationStatus.failed
    assert stored.error == "AI_API_KEY is not configured"
