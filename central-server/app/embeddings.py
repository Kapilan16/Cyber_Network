"""Embedding providers used to rebuild central SharedIntel vectors."""
from __future__ import annotations

import hashlib
import logging
import math
import re
import threading
from typing import Sequence

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class EmbeddingsClient:
    """Provider dispatcher with one lazily loaded CPU sentence-transformer."""

    def __init__(self) -> None:
        self._provider = settings.EMBEDDING_PROVIDER
        self._dimension = settings.CENTRAL_VECTOR_DIM
        self._local_model_name = settings.LOCAL_EMBEDDING_MODEL
        self._api_key = settings.EMBEDDINGS_API_KEY
        self._api_url = settings.EMBEDDINGS_API_URL
        self._api_model = settings.EMBEDDINGS_MODEL
        self._sentence_model = None
        self._model_load_attempted = False
        self._model_lock = threading.Lock()

    def initialize(self) -> bool:
        """Load the configured local model once, typically before a rebuild."""
        if self._provider != "local_sentence_transformers":
            return True
        try:
            self._get_sentence_model()
            return True
        except Exception:
            logger.exception("Unable to initialize central embedding model")
            return False

    def embed(self, text: str) -> list[float] | None:
        if not text or not text.strip():
            return None
        if self._provider == "feature_hash":
            return self._feature_hash(text)
        if self._provider == "local_sentence_transformers":
            try:
                model = self._get_sentence_model()
                encoded = model.encode(
                    text[:8192],
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                    show_progress_bar=False,
                    device="cpu",
                )
                return self._fit_dimension(encoded)
            except Exception:
                logger.exception(
                    "Central sentence-transformer failed; using feature-hash fallback"
                )
                return self._feature_hash(text)
        if self._provider == "openai_compatible":
            if not self._api_key:
                logger.error(
                    "EMBEDDINGS_API_KEY is required when EMBEDDING_PROVIDER="
                    "openai_compatible"
                )
                return None
            try:
                return self._fit_dimension(self._call_api(text))
            except Exception:
                logger.exception("Central OpenAI-compatible embedding request failed")
                return None
        logger.error("Unsupported central embedding provider: %s", self._provider)
        return None

    def _get_sentence_model(self):
        if self._sentence_model is not None:
            return self._sentence_model
        with self._model_lock:
            if self._sentence_model is not None:
                return self._sentence_model
            if self._model_load_attempted:
                raise RuntimeError("Central sentence-transformer previously failed to load")
            self._model_load_attempted = True
            from sentence_transformers import SentenceTransformer

            self._sentence_model = SentenceTransformer(
                self._local_model_name,
                device="cpu",
            )
            return self._sentence_model

    def _fit_dimension(self, values: Sequence[float]) -> list[float]:
        if hasattr(values, "tolist"):
            values = values.tolist()
        result = [float(value) for value in values[: self._dimension]]
        result.extend([0.0] * (self._dimension - len(result)))
        if any(not math.isfinite(value) for value in result):
            raise ValueError("Embedding provider returned a non-finite value")
        return result

    def _feature_hash(self, text: str) -> list[float]:
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

    def _call_api(self, text: str) -> list[float]:
        with httpx.Client(timeout=8.0) as http:
            response = http.post(
                self._api_url,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={"input": text[:8192], "model": self._api_model},
            )
            response.raise_for_status()
            data = response.json()
        try:
            return [float(value) for value in data["data"][0]["embedding"]]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ValueError(f"Unexpected embeddings API response shape: {exc}") from exc


_client: EmbeddingsClient | None = None
_client_lock = threading.Lock()


def get_embeddings_client() -> EmbeddingsClient:
    """Return the process-wide embedding provider client."""
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = EmbeddingsClient()
    return _client
