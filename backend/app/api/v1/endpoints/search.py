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
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.api.deps import get_current_user
from app.core.database import get_db
from app.embeddings.client import get_embeddings_client
from app.models.raw_submission import RawSubmission
from app.models.user import User, UserRole

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/search", tags=["search"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class SemanticSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000,
                       description="Natural-language search query")
    top_k: int = Field(10, ge=1, le=50,
                       description="Maximum number of results to return")


class SearchResult(BaseModel):
    id: int
    source_type: str
    sanitized_text_preview: str   # first 300 chars of sanitized text
    similarity: float             # cosine similarity ∈ [0, 1]
    submitted_at: str             # ISO-8601
    embedding_status: str


class SemanticSearchResponse(BaseModel):
    results: List[SearchResult]
    query: str
    top_k: int
    total_found: int


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


# ── Route ─────────────────────────────────────────────────────────────────────

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
    results = run_vector_search(
        db=db,
        query_embedding=query_embedding,
        user_id=current_user.id,
        top_k=body.top_k,
        is_admin=is_admin,
    )

    return SemanticSearchResponse(
        results=results,
        query=body.query,
        top_k=body.top_k,
        total_found=len(results),
    )
