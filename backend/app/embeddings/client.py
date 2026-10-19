"""
Embeddings client supporting a local sentence-transformer, an OpenAI-compatible
API, and deterministic feature hashing.

Design principles:
- embed() NEVER raises; returns None on any failure.
- Timeout + exponential-backoff retry (max 2 retries).
- API key read from settings; no hardcoded secrets.
- The local sentence-transformer is loaded once, on first use, on CPU.
- Model-load/inference failures fall back to deterministic feature hashing.
- Every provider returns exactly VECTOR_DIM values for the existing pgvector schema.
"""
from __future__ import annotations

import logging
import hashlib
import math
import re
import threading
import time
from typing import List, Optional, Sequence

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Retry config ─────────────────────────────────────────────────────────────
_TIMEOUT       = 8.0   # seconds total
_MAX_RETRIES   = 2
_RETRY_DELAY   = 0.5   # first retry wait (seconds); doubles each attempt


class EmbeddingsClient:
    """Synchronous embeddings provider with a lazily loaded local model."""

    def __init__(self) -> None:
        self._api_key  = settings.EMBEDDINGS_API_KEY
        self._api_url  = settings.EMBEDDINGS_API_URL
        self._model    = settings.EMBEDDINGS_MODEL
        self._provider = settings.EMBEDDING_PROVIDER
        self._local_model_name = settings.LOCAL_EMBEDDING_MODEL
        configured_dimension = getattr(settings, "VECTOR_DIM", 1536)
        self._dimension = configured_dimension if isinstance(configured_dimension, int) else 1536
        self._sentence_model = None
        self._model_load_attempted = False
        self._model_lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def embed(self, text: str) -> Optional[List[float]]:
        """
        Return a fixed-width vector or None when the selected provider fails.

        Local model load or inference errors use the feature-hash fallback.
        OpenAI-compatible API errors return None so intake stays non-blocking.
        """
        if not text or not text.strip():
            return None

        if self._provider == "feature_hash":
            return self._local_embedding(text)
        if self._provider == "local_sentence_transformers":
            if self._model_load_attempted and self._sentence_model is None:
                return self._local_embedding(text)
            try:
                model = self._get_sentence_model()
                vector = model.encode(
                    text[:8192],
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                    show_progress_bar=False,
                    device="cpu",
                )
                return self._fit_dimension(vector)
            except Exception:
                logger.exception(
                    "Local embedding model failed; using feature-hash fallback"
                )
                return self._local_embedding(text)
        if self._provider != "openai_compatible":
            logger.error("Unsupported embedding provider: %s", self._provider)
            return None
        if not self._api_key:
            logger.error(
                "EMBEDDINGS_API_KEY is required when EMBEDDING_PROVIDER="
                "openai_compatible"
            )
            return None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                return self._fit_dimension(self._call(text))
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

    def initialize(self) -> bool:
        """Warm the configured local model during application startup."""
        if self._provider != "local_sentence_transformers":
            return True
        try:
            self._get_sentence_model()
            return True
        except Exception:
            logger.exception(
                "Unable to initialize local embedding model; "
                "feature-hash fallback will be used"
            )
            return False

    def _get_sentence_model(self):
        if self._sentence_model is not None:
            return self._sentence_model
        with self._model_lock:
            if self._sentence_model is not None:
                return self._sentence_model
            if self._model_load_attempted:
                raise RuntimeError("Local sentence-transformer previously failed to load")
            self._model_load_attempted = True
            from sentence_transformers import SentenceTransformer

            self._sentence_model = SentenceTransformer(
                self._local_model_name,
                device="cpu",
            )
            return self._sentence_model

    def _fit_dimension(self, values: Sequence[float]) -> List[float]:
        """Zero-pad or truncate provider output to the pgvector storage width."""
        if hasattr(values, "tolist"):
            values = values.tolist()
        result = [float(value) for value in values[: self._dimension]]
        if len(result) < self._dimension:
            result.extend([0.0] * (self._dimension - len(result)))
        if any(not math.isfinite(value) for value in result):
            raise ValueError("Embedding provider returned a non-finite value")
        return result

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
_client_lock = threading.Lock()


def get_embeddings_client() -> EmbeddingsClient:
    """Return the process-wide client; its sentence-transformer is lazy-loaded once."""
    global _client  # noqa: PLW0603
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = EmbeddingsClient()
    return _client
