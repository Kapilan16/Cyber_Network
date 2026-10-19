"""
Semantic search endpoint.

POST /api/search/semantic
  { "query": "...", "top_k": 10 }

Embeds the query via the configured embeddings API, then runs a cosine-
similarity nearest-neighbour query using pgvector's <=> operator against
sanitized submission embeddings.

Design:
- If the embedding API call fails, return HTTP 503.
- Results are scoped by ownership (admin sees all; analyst sees own).
- run_vector_search() is isolated for easy mocking in tests.
"""
from __future__ import annotations

import json
import logging
import math
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.api.deps import get_current_admin, get_current_user
from app.central_client import (
    CentralClient,
    CentralClientConfigurationError,
    CentralRequestError,
    CentralUnavailableError,
)
from app.core.database import get_db
from app.core.config import settings
from app.embeddings.client import get_embeddings_client
from app.models.raw_submission import EmbeddingStatus, RawSubmission
from app.models.user import User, UserRole
from app.search.faiss_index import get_faiss_index

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/search", tags=["search"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class SemanticSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000,
                       description="Natural-language search query")
    top_k: int = Field(10, ge=1, le=50,
                       description="Maximum number of results to return")
    search_network: bool = Field(
        False,
        description="Also search anonymized incidents shared by other organizations",
    )


class SearchResult(BaseModel):
    id: int
    source_type: str
    sanitized_text_preview: str   # first 300 chars of sanitized text
    similarity: float             # cosine similarity ∈ [0, 1]
    submitted_at: str             # ISO-8601
    embedding_status: str


class SemanticSearchResponse(BaseModel):
    results: List[SearchResult]
    network_results: List["NetworkSearchResult"] = Field(default_factory=list)
    network_search_attempted: bool = False
    network_search_error: Optional[str] = None
    query: str
    top_k: int
    total_found: int


class NetworkSearchResult(BaseModel):
    sanitized_text: str
    mitre_technique_ids: List[str]
    severity: List[str]
    similarity_score: float


# ── Abstracted vector search (mockable in tests) ──────────────────────────────

def run_vector_search(
    db: Session,
    query_embedding: List[float],
    user_id: int,
    top_k: int,
    is_admin: bool = False,
) -> List[SearchResult]:
    """
    Execute cosine-similarity nearest-neighbour search using pgvector.

    Returns a list of SearchResult dicts ordered by descending similarity.
    Returns [] gracefully if pgvector is not available or any error occurs.
    """
    try:
        # Format embedding as pgvector literal: "[0.1,0.2,...]"
        vec_literal = "[" + ",".join(f"{x:.8f}" for x in query_embedding) + "]"

        scope_clause = "" if is_admin else "AND user_id = :user_id"

        sql = text(f"""
            SELECT
                id,
                source_type,
                sanitized_text,
                submitted_at,
                embedding_status,
                1 - (embedding <=> CAST(:vec AS vector)) AS similarity
            FROM raw_submissions
            WHERE embedding IS NOT NULL
              AND embedding_status = 'complete'
              {scope_clause}
            ORDER BY embedding <=> CAST(:vec AS vector) ASC
            LIMIT :top_k
        """)

        params: dict = {"vec": vec_literal, "top_k": top_k}
        if not is_admin:
            params["user_id"] = user_id

        rows = db.execute(sql, params).fetchall()

        return [
            SearchResult(
                id=row.id,
                source_type=row.source_type,
                sanitized_text_preview=(row.sanitized_text or "")[:300],
                similarity=round(float(row.similarity), 4),
                submitted_at=row.submitted_at.isoformat()
                    if hasattr(row.submitted_at, "isoformat")
                    else str(row.submitted_at),
                embedding_status=row.embedding_status,
            )
            for row in rows
        ]
    except Exception as exc:  # noqa: BLE001
        logger.error("Vector search failed: %s", exc)
        return []


def _run_faiss_search(
    db: Session,
    query_embedding: List[float],
    user_id: int,
    top_k: int,
    is_admin: bool = False,
) -> List[SearchResult] | None:
    """Search FAISS candidates, then validate and rescore them from pgvector rows."""
    index = get_faiss_index()
    if not index.available or index.count == 0:
        return None

    indexed_count = index.count
    candidate_count = min(indexed_count, max(top_k * 4, top_k))
    while True:
        candidates = index.search(query_embedding, candidate_count)
        if candidates is None:
            return None
        candidate_ids = [item_id for item_id, _score in candidates]
        query = db.query(RawSubmission).filter(
            RawSubmission.id.in_(candidate_ids),
            RawSubmission.embedding.is_not(None),
            RawSubmission.embedding_status == EmbeddingStatus.complete,
        )
        if not is_admin:
            query = query.filter(RawSubmission.user_id == user_id)
        records = {record.id: record for record in query.all()}

        query_norm = math.sqrt(sum(value * value for value in query_embedding))
        matches: list[SearchResult] = []
        for item_id, _faiss_score in candidates:
            record = records.get(item_id)
            if record is None:
                continue
            vector = record.embedding
            if isinstance(vector, str):
                try:
                    vector = json.loads(vector)
                except (TypeError, ValueError):
                    continue
            if not isinstance(vector, (list, tuple)) or len(vector) != len(query_embedding):
                continue
            vector_values = [float(value) for value in vector]
            vector_norm = math.sqrt(sum(value * value for value in vector_values))
            similarity = (
                sum(left * right for left, right in zip(query_embedding, vector_values))
                / (query_norm * vector_norm)
                if query_norm and vector_norm
                else 0.0
            )
            matches.append(
                SearchResult(
                    id=record.id,
                    source_type=record.source_type.value
                    if hasattr(record.source_type, "value")
                    else str(record.source_type),
                    sanitized_text_preview=(record.sanitized_text or "")[:300],
                    similarity=round(similarity, 4),
                    submitted_at=record.submitted_at.isoformat()
                    if hasattr(record.submitted_at, "isoformat")
                    else str(record.submitted_at),
                    embedding_status=record.embedding_status.value
                    if hasattr(record.embedding_status, "value")
                    else str(record.embedding_status),
                )
            )
        matches.sort(key=lambda result: result.similarity, reverse=True)
        if len(matches) >= top_k or candidate_count >= indexed_count:
            return matches[:top_k]
        candidate_count = min(indexed_count, candidate_count * 2)


def run_faiss_search(
    db: Session,
    query_embedding: List[float],
    user_id: int,
    top_k: int,
    is_admin: bool = False,
) -> List[SearchResult] | None:
    """Return None on index/database errors so callers can use pgvector."""
    try:
        return _run_faiss_search(
            db,
            query_embedding,
            user_id,
            top_k,
            is_admin,
        )
    except Exception:
        logger.exception("FAISS submission search failed; falling back to pgvector")
        return None


# ── Route ─────────────────────────────────────────────────────────────────────

@router.get(
    "/semantic/benchmark",
    summary="Compare FAISS and pgvector semantic-search latency",
)
def semantic_search_benchmark(
    query: str = Query(..., min_length=1, max_length=2000),
    top_k: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    _admin: User = Depends(get_current_admin),
) -> dict:
    """Development-only benchmark; not used by the demo UI."""
    if settings.ENVIRONMENT.lower() not in {"development", "dev", "test"}:
        raise HTTPException(status_code=404, detail="Not found")
    embedding = get_embeddings_client().embed(query)
    if embedding is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Embedding service unavailable",
        )

    started = time.perf_counter()
    faiss_results = run_faiss_search(
        db, embedding, _admin.id, top_k, is_admin=True
    )
    faiss_latency_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    pgvector_results = run_vector_search(
        db, embedding, _admin.id, top_k, is_admin=True
    )
    pgvector_latency_ms = (time.perf_counter() - started) * 1000
    return {
        "faiss_available": faiss_results is not None,
        "faiss_latency_ms": round(faiss_latency_ms, 3)
        if faiss_results is not None
        else None,
        "pgvector_latency_ms": round(pgvector_latency_ms, 3),
        "faiss_result_count": len(faiss_results or []),
        "pgvector_result_count": len(pgvector_results),
    }


@router.post(
    "/semantic",
    response_model=SemanticSearchResponse,
    status_code=status.HTTP_200_OK,
    summary="Semantic nearest-neighbour search over submissions",
)
def semantic_search(
    body: SemanticSearchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SemanticSearchResponse:
    """
    Embeds the query text and returns the *top_k* most similar past submissions
    ranked by cosine similarity.

    - Analysts only see their own submissions.
    - Admins see all submissions.
    - Returns HTTP 503 if the embeddings API is unreachable.
    """
    client = get_embeddings_client()
    query_embedding: Optional[List[float]] = client.embed(body.query)

    if query_embedding is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Embeddings service unavailable — either the API key is not "
                "configured or the service is temporarily unreachable. "
                "Please try again later."
            ),
        )

    is_admin = current_user.role == UserRole.admin
    results = run_faiss_search(
        db=db,
        query_embedding=query_embedding,
        user_id=current_user.id,
        top_k=body.top_k,
        is_admin=is_admin,
    )
    if results is None:
        results = run_vector_search(
            db=db,
            query_embedding=query_embedding,
            user_id=current_user.id,
            top_k=body.top_k,
            is_admin=is_admin,
        )

    network_results: List[NetworkSearchResult] = []
    network_error: Optional[str] = None
    if body.search_network:
        try:
            with CentralClient() as central:
                network_response = central.search_intel(
                    query_embedding,
                    top_k=body.top_k,
                )
            network_results = [
                NetworkSearchResult(
                    sanitized_text=str(item["sanitized_text"]),
                    mitre_technique_ids=list(item.get("mitre_technique_ids", [])),
                    severity=list(item.get("severity", [])),
                    similarity_score=round(float(item["similarity_score"]), 4),
                )
                for item in network_response.get("results", [])
            ]
        except CentralClientConfigurationError:
            network_error = "Network search is not configured for this deployment."
        except CentralUnavailableError:
            network_error = "The central network is unavailable. Local results are still shown."
        except CentralRequestError:
            logger.exception("Central network search was rejected")
            network_error = "The central network could not complete this search."
        except (KeyError, TypeError, ValueError):
            logger.exception("Central network returned an invalid search response")
            network_error = "The central network returned an invalid response."

    return SemanticSearchResponse(
        results=results,
        network_results=network_results,
        network_search_attempted=body.search_network,
        network_search_error=network_error,
        query=body.query,
        top_k=body.top_k,
        total_found=len(results) + len(network_results),
    )
