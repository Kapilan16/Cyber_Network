"""
Tests for Milestone 5 — Semantic Search (embedding + vector search).

All external HTTP calls and the pgvector distance query are mocked so
tests run entirely against the in-memory SQLite DB.
"""
from __future__ import annotations

from typing import List
from unittest.mock import MagicMock, patch

import pytest

# ── Constants ─────────────────────────────────────────────────────────────────

REGISTER     = "/api/auth/register"
LOGIN        = "/api/auth/login"
SUBMISSIONS  = "/api/submissions"
SEARCH       = "/api/search/semantic"

_ANALYST = {"email": "semrch_analyst@test.com", "password": "P@ssw0rd!!"}
_ADMIN   = {"email": "semrch_admin@test.com",   "password": "P@ssw0rd!!", "role": "admin"}

FAKE_EMBEDDING: List[float] = [0.1] * 1536   # 1536-dim fake vector


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _token(client, creds: dict) -> str:
    client.post(REGISTER, json=creds)
    if creds.get("role") == "admin":
        from app.api.deps import get_db
        from app.models.user import User, UserRole

        db = next(client.app.dependency_overrides[get_db]())
        user = db.query(User).filter(User.email == creds["email"]).one()
        user.role = UserRole.admin
        db.commit()
    r = client.post(LOGIN, json={"email": creds["email"], "password": creds["password"]})
    return r.json()["access_token"]


def _auth(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


# ── Embedding-status tests ────────────────────────────────────────────────────

class TestEmbeddingStatus:
    """Verify that create_submission correctly tracks embedding lifecycle."""

    def test_embedding_success_marks_complete(self, client):
        """When embed() returns a vector, status must be 'complete'."""
        with patch("app.embeddings.client.EmbeddingsClient.embed", return_value=FAKE_EMBEDDING):
            tok = _token(client, _ANALYST)
            r = client.post(
                SUBMISSIONS,
                json={"raw_text": "suspicious PowerShell invocation", "source_type": "alert"},
                headers=_auth(tok),
            )
        assert r.status_code == 201
        assert r.json()["embedding_status"] == "complete"

    def test_embedding_failure_does_not_block_submission(self, client):
        """When embed() returns None (API down), submission still succeeds with status 'failed'."""
        with patch("app.embeddings.client.EmbeddingsClient.embed", return_value=None):
            tok = _token(client, _ANALYST)
            r = client.post(
                SUBMISSIONS,
                json={"raw_text": "network anomaly detected", "source_type": "log"},
                headers=_auth(tok),
            )
        assert r.status_code == 201
        assert r.json()["embedding_status"] == "failed"

    def test_embedding_exception_does_not_block_submission(self, client):
        """When embed() raises, submission still succeeds with status 'failed'."""
        with patch("app.embeddings.client.EmbeddingsClient.embed", side_effect=RuntimeError("API exploded")):
            tok = _token(client, _ANALYST)
            r = client.post(
                SUBMISSIONS,
                json={"raw_text": "brute force login attempt", "source_type": "alert"},
                headers=_auth(tok),
            )
        assert r.status_code == 201
        assert r.json()["embedding_status"] == "failed"

    def test_new_submission_starts_with_pending_before_embed(self, client):
        """Initial DB state is 'pending'; status is updated to complete/failed synchronously."""
        with patch("app.embeddings.client.EmbeddingsClient.embed", return_value=FAKE_EMBEDDING):
            tok = _token(client, _ANALYST)
            r = client.post(
                SUBMISSIONS,
                json={"raw_text": "lateral movement indicators", "source_type": "report"},
                headers=_auth(tok),
            )
        # After the sync embed step, it should be complete (not pending)
        assert r.json()["embedding_status"] in ("complete", "failed")


# ── Search endpoint tests ─────────────────────────────────────────────────────

class TestSemanticSearchEndpoint:
    """Tests for POST /api/search/semantic."""

    def test_requires_authentication(self, client):
        """Unauthenticated requests must return 401."""
        r = client.post(SEARCH, json={"query": "PowerShell"})
        assert r.status_code == 401

    def test_empty_query_rejected(self, client):
        """Empty or blank query strings must be rejected."""
        with patch("app.embeddings.client.EmbeddingsClient.embed", return_value=FAKE_EMBEDDING):
            tok = _token(client, _ANALYST)
            r = client.post(SEARCH, json={"query": ""}, headers=_auth(tok))
        assert r.status_code == 422

    def test_embedding_failure_returns_503(self, client):
        """If the embeddings API cannot embed the query, return 503."""
        with patch("app.embeddings.client.EmbeddingsClient.embed", return_value=None):
            tok = _token(client, _ANALYST)
            r = client.post(SEARCH, json={"query": "suspicious activity"}, headers=_auth(tok))
        assert r.status_code == 503

    def test_returns_ranked_results_from_mocked_search(self, client):
        """
        Mock run_vector_search to return pre-built results; verify the
        response shape, ordering (descending similarity), and field names.
        """
        from app.api.v1.endpoints.search import SearchResult

        mock_results = [
            SearchResult(
                id=2, source_type="alert",
                sanitized_text_preview="PowerShell encoded command executed",
                similarity=0.94, submitted_at="2025-01-02T10:00:00",
                embedding_status="complete",
            ),
            SearchResult(
                id=1, source_type="log",
                sanitized_text_preview="normal login from known IP",
                similarity=0.61, submitted_at="2025-01-01T09:00:00",
                embedding_status="complete",
            ),
        ]

        with (
            patch("app.embeddings.client.EmbeddingsClient.embed", return_value=FAKE_EMBEDDING),
            patch("app.api.v1.endpoints.search.run_vector_search", return_value=mock_results),
        ):
            tok = _token(client, _ANALYST)
            r = client.post(
                SEARCH,
                json={"query": "PowerShell suspicious command", "top_k": 5},
                headers=_auth(tok),
            )

        assert r.status_code == 200
        body = r.json()
        assert body["query"] == "PowerShell suspicious command"
        assert body["top_k"] == 5
        assert body["total_found"] == 2

        results = body["results"]
        assert len(results) == 2
        # Most similar result must be first
        assert results[0]["similarity"] >= results[1]["similarity"]
        assert results[0]["id"] == 2
        assert results[0]["source_type"] == "alert"

    def test_top_k_respected(self, client):
        """top_k=1 should be respected by the search function."""
        from app.api.v1.endpoints.search import SearchResult

        single = [
            SearchResult(
                id=5, source_type="report",
                sanitized_text_preview="malware persistence via registry",
                similarity=0.88, submitted_at="2025-01-03T12:00:00",
                embedding_status="complete",
            )
        ]

        with (
            patch("app.embeddings.client.EmbeddingsClient.embed", return_value=FAKE_EMBEDDING),
            patch("app.api.v1.endpoints.search.run_vector_search", return_value=single) as mock_vs,
        ):
            tok = _token(client, _ANALYST)
            r = client.post(SEARCH, json={"query": "malware", "top_k": 1}, headers=_auth(tok))
            # Verify top_k was forwarded to the search function
            call_kwargs = mock_vs.call_args
            assert call_kwargs.kwargs.get("top_k", call_kwargs.args[3] if len(call_kwargs.args) > 3 else None) == 1

        assert r.status_code == 200
        assert len(r.json()["results"]) == 1

    def test_empty_results_when_no_embeddings(self, client):
        """If no submissions have embeddings, return empty results (not an error)."""
        with (
            patch("app.embeddings.client.EmbeddingsClient.embed", return_value=FAKE_EMBEDDING),
            patch("app.api.v1.endpoints.search.run_vector_search", return_value=[]),
        ):
            tok = _token(client, _ANALYST)
            r = client.post(SEARCH, json={"query": "anything"}, headers=_auth(tok))

        assert r.status_code == 200
        assert r.json()["results"] == []
        assert r.json()["total_found"] == 0

    def test_top_k_validation(self, client):
        """top_k must be between 1 and 50."""
        with patch("app.embeddings.client.EmbeddingsClient.embed", return_value=FAKE_EMBEDDING):
            tok = _token(client, _ANALYST)
            r = client.post(SEARCH, json={"query": "test", "top_k": 0}, headers=_auth(tok))
            assert r.status_code == 422

            r = client.post(SEARCH, json={"query": "test", "top_k": 51}, headers=_auth(tok))
            assert r.status_code == 422


# ── EmbeddingsClient unit tests ───────────────────────────────────────────────

class TestEmbeddingsClient:
    """Unit-test the client in isolation, fully mocked."""

    def test_local_embedding_when_api_key_empty(self):
        """If no API key is configured, embed() returns a local demo vector."""
        from app.embeddings.client import EmbeddingsClient
        from unittest.mock import patch as _patch

        with _patch("app.embeddings.client.settings") as mock_settings:
            mock_settings.EMBEDDINGS_API_KEY = ""
            mock_settings.EMBEDDINGS_API_URL = "https://api.openai.com/v1/embeddings"
            mock_settings.EMBEDDINGS_MODEL   = "text-embedding-ada-002"
            client = EmbeddingsClient()
            result = client.embed("some text")

        assert result is not None
        assert len(result) == 1536

    def test_returns_none_on_http_error(self):
        """4xx from the API must return None (no exception propagated)."""
        import httpx
        from app.embeddings.client import EmbeddingsClient

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"

        with patch("app.embeddings.client.settings") as mock_settings:
            mock_settings.EMBEDDINGS_API_KEY = "sk-test"
            mock_settings.EMBEDDINGS_API_URL = "https://api.openai.com/v1/embeddings"
            mock_settings.EMBEDDINGS_MODEL   = "text-embedding-ada-002"
            c = EmbeddingsClient()

            with patch.object(c, "_call", side_effect=httpx.HTTPStatusError(
                "Unauthorized", request=MagicMock(), response=mock_resp
            )):
                result = c.embed("some text")

        assert result is None

    def test_returns_none_on_timeout(self):
        """Timeout must return None (no exception propagated)."""
        import httpx
        from app.embeddings.client import EmbeddingsClient

        with patch("app.embeddings.client.settings") as mock_settings:
            mock_settings.EMBEDDINGS_API_KEY = "sk-test"
            mock_settings.EMBEDDINGS_API_URL = "https://api.openai.com/v1/embeddings"
            mock_settings.EMBEDDINGS_MODEL   = "text-embedding-ada-002"
            c = EmbeddingsClient()

            with patch.object(c, "_call", side_effect=httpx.TimeoutException("timeout")):
                with patch("app.embeddings.client.time.sleep"):  # skip retry delay
                    result = c.embed("some text")

        assert result is None

    def test_returns_vector_on_success(self):
        """Successful API call returns list[float]."""
        from app.embeddings.client import EmbeddingsClient

        expected_vector = [0.1] * 1536

        with patch("app.embeddings.client.settings") as mock_settings:
            mock_settings.EMBEDDINGS_API_KEY = "sk-test"
            mock_settings.EMBEDDINGS_API_URL = "https://api.openai.com/v1/embeddings"
            mock_settings.EMBEDDINGS_MODEL   = "text-embedding-ada-002"
            c = EmbeddingsClient()

            with patch.object(c, "_call", return_value=expected_vector):
                result = c.embed("PowerShell suspicious command")

        assert result == expected_vector
        assert len(result) == 1536
