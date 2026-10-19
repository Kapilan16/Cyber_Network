"""In-memory FAISS index for org-local submission embeddings."""
from __future__ import annotations

import logging
import threading
from collections.abc import Iterable

import numpy as np

from app.core.config import settings

logger = logging.getLogger(__name__)


class FaissVectorIndex:
    """A replaceable IndexFlatIP plus a position-to-submission ID mapping."""

    def __init__(self, dimension: int | None = None) -> None:
        self._configured_dimension = dimension or settings.VECTOR_DIM
        self._dimension = self._configured_dimension
        self._index = None
        self._ids: list[int] = []
        self._ready = False
        self._faiss = None
        self._rebuilding = False
        self._pending_adds: list[tuple[int, list[float]]] = []
        self._pending_updates = False
        self._lock = threading.RLock()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._ids)

    @property
    def available(self) -> bool:
        with self._lock:
            return self._ready and self._index is not None

    def rebuild(self, entries: Iterable[tuple[int, object]]) -> bool:
        """Atomically replace the index from (submission ID, vector) entries."""
        with self._lock:
            self._rebuilding = True
            self._pending_adds = []
            self._pending_updates = False
        try:
            faiss = self._load_faiss()
            indexed_ids: list[int] = []
            vectors: list[list[float]] = []
            dimension = self._configured_dimension
            for item_id, values in entries:
                vector = self._normalize(values)
                if vector is None:
                    continue
                if len(vector) != dimension:
                    logger.warning(
                        "Skipping submission %s with an embedding dimension mismatch",
                        item_id,
                    )
                    continue
                indexed_ids.append(int(item_id))
                vectors.append(vector)

            index = faiss.IndexFlatIP(dimension)
            if vectors:
                index.add(np.asarray(vectors, dtype=np.float32))
            with self._lock:
                seen_ids = set(indexed_ids)
                for item_id, vector in self._pending_adds:
                    if item_id in seen_ids or len(vector) != dimension:
                        self._pending_updates = True
                        continue
                    index.add(np.asarray([vector], dtype=np.float32))
                    indexed_ids.append(item_id)
                    seen_ids.add(item_id)
                self._faiss = faiss
                self._dimension = dimension
                self._index = index
                self._ids = indexed_ids
                self._ready = not self._pending_updates
                self._rebuilding = False
                self._pending_adds = []
                self._pending_updates = False
            return True
        except Exception:
            logger.exception("Unable to build submission FAISS index")
            with self._lock:
                self._ready = False
                self._rebuilding = False
                self._pending_adds = []
                self._pending_updates = False
            return False

    def add(self, item_id: int, values: object) -> bool:
        """Append a new unique embedding; updates require a full rebuild."""
        vector = self._normalize(values)
        if vector is None:
            return False
        with self._lock:
            if self._rebuilding:
                if int(item_id) in self._ids or any(
                    pending_id == int(item_id)
                    for pending_id, _pending_vector in self._pending_adds
                ):
                    self._pending_updates = True
                    return False
                self._pending_adds.append((int(item_id), vector))
                return True
            if not self._ready or self._index is None:
                return False
            if int(item_id) in self._ids:
                self._ready = False
                return False
            if len(vector) != self._dimension:
                if self._ids:
                    self._ready = False
                    return False
                try:
                    self._index = self._load_faiss().IndexFlatIP(len(vector))
                    self._dimension = len(vector)
                except Exception:
                    logger.exception("Unable to resize empty submission FAISS index")
                    self._ready = False
                    return False
            try:
                self._index.add(np.asarray([vector], dtype=np.float32))
                self._ids.append(int(item_id))
                return True
            except Exception:
                logger.exception("Unable to add submission %s to FAISS index", item_id)
                self._ready = False
                return False

    def search(self, query: object, limit: int) -> list[tuple[int, float]] | None:
        """Return nearest (submission ID, inner-product score) pairs, or None if cold."""
        vector = self._normalize(query)
        if vector is None or limit <= 0:
            return None
        with self._lock:
            if self._rebuilding or not self._ready or self._index is None or not self._ids:
                return None
            if len(vector) != self._dimension:
                return None
            count = min(limit, len(self._ids))
            try:
                scores, positions = self._index.search(
                    np.asarray([vector], dtype=np.float32),
                    count,
                )
                return [
                    (self._ids[int(position)], float(score))
                    for position, score in zip(positions[0], scores[0])
                    if int(position) >= 0
                ]
            except Exception:
                logger.exception("Submission FAISS search failed")
                return None

    def _normalize(self, values: object) -> list[float] | None:
        try:
            if isinstance(values, str):
                import json

                values = json.loads(values)
            if hasattr(values, "tolist"):
                values = values.tolist()
            vector = [float(value) for value in values]  # type: ignore[union-attr]
            if not vector or not np.isfinite(vector).all():
                return None
            norm = float(np.linalg.norm(np.asarray(vector, dtype=np.float32)))
            if not norm:
                return None
            return [value / norm for value in vector]
        except (TypeError, ValueError):
            return None

    def _load_faiss(self):
        if self._faiss is None:
            import faiss

            self._faiss = faiss
        return self._faiss


_faiss_index = FaissVectorIndex()


def get_faiss_index() -> FaissVectorIndex:
    return _faiss_index
