"""
Embeddings client — wraps an OpenAI-compatible embeddings API via httpx.

Design principles:
- embed() NEVER raises; returns None on any failure.
- Timeout + exponential-backoff retry (max 2 retries).
- API key read from settings; no hardcoded secrets.
- Without an API key, a deterministic local feature-hash vector supports demos.
- Configured-provider failures return None and never block submission intake.
"""
from __future__ import annotations

import logging
import hashlib
import math
import re
import time
from typing import List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Retry config ─────────────────────────────────────────────────────────────
_TIMEOUT       = 8.0   # seconds total
_MAX_RETRIES   = 2
_RETRY_DELAY   = 0.5   # first retry wait (seconds); doubles each attempt


class EmbeddingsClient:
    """Synchronous OpenAI-compatible embeddings client."""

    def __init__(self) -> None:
        self._api_key  = settings.EMBEDDINGS_API_KEY
        self._api_url  = settings.EMBEDDINGS_API_URL
        self._model    = settings.EMBEDDINGS_MODEL
        configured_dimension = getattr(settings, "VECTOR_DIM", 1536)
        self._dimension = configured_dimension if isinstance(configured_dimension, int) else 1536

    # ── Public API ────────────────────────────────────────────────────────────

    def embed(self, text: str) -> Optional[List[float]]:
        """
        Return the embedding vector for *text*, or None on any failure.

        Without an API key, return a deterministic local feature-hash vector
        for demo use. Configured-provider failures remain non-blocking.

        Failure cases handled gracefully (no exception propagation):
        - HTTP errors / 4xx / 5xx
        - Timeout
        - Unexpected response shape
        """
        if not self._api_key:
            return self._local_embedding(text)

        if not text or not text.strip():
            return None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                return self._call(text)
            except httpx.TimeoutException as exc:
                logger.warning("Embedding timeout (attempt %d/%d): %s", attempt + 1, _MAX_RETRIES + 1, exc)
            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                # 4xx errors are non-retriable
                if 400 <= status_code < 500:
                    logger.error("Embedding API client error %d: %s", status_code, exc.response.text[:200])
                    return None
                logger.warning("Embedding API server error %d (attempt %d/%d)", status_code, attempt + 1, _MAX_RETRIES + 1)
            except Exception as exc:  # noqa: BLE001
                logger.error("Unexpected embedding error: %s", exc)
                return None

            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY * (2 ** attempt))

        logger.error("Embedding failed after %d attempts — marking as failed.", _MAX_RETRIES + 1)
        return None

    def _local_embedding(self, text: str) -> List[float]:
        """Create a normalized feature-hash vector for offline demo search."""
        tokens = re.findall(r"[a-z0-9_.-]+", text.lower())
        features = [(token, 1.0) for token in tokens]
        features.extend(
            (f"{left} {right}", 0.65)
            for left, right in zip(tokens, tokens[1:])
        )
        vector = [0.0] * self._dimension
        for feature, weight in features:
            digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
            value = int.from_bytes(digest, "little")
            index = value % self._dimension
            vector[index] += weight if value & (1 << 63) else -weight
        magnitude = math.sqrt(sum(value * value for value in vector))
        if magnitude:
            return [value / magnitude for value in vector]
        return vector

    # ── Private helpers ───────────────────────────────────────────────────────

    def _call(self, text: str) -> List[float]:
        """Single HTTP request to the embeddings API. May raise httpx exceptions."""
        payload = {
            "input": text[:8192],   # guard against absurdly long text
            "model": self._model,
        }
        with httpx.Client(timeout=_TIMEOUT) as http:
            response = http.post(
                self._api_url,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        # OpenAI format: {"data": [{"embedding": [...]}], ...}
        try:
            return [float(x) for x in data["data"][0]["embedding"]]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ValueError(f"Unexpected embeddings API response shape: {exc}") from exc


# ── Module-level singleton (lazy) ─────────────────────────────────────────────

_client: Optional[EmbeddingsClient] = None


def get_embeddings_client() -> EmbeddingsClient:
    """Return the shared singleton EmbeddingsClient (thread-safe at module level)."""
    global _client  # noqa: PLW0603
    if _client is None:
        _client = EmbeddingsClient()
    return _client
