"""Central Cyber Memory Network registration API."""
import asyncio
import secrets
import hashlib
import json
import logging
import math
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from app.config import settings
from app.database import SessionLocal, get_db
from app.dependencies import get_current_org
from app.models import Organization, SharedIntel
from app.search.faiss_index import get_faiss_index
from app.schemas import (
    OrganizationIdentity,
    OrganizationListItem,
    OrganizationRegistration,
    OrganizationRegistrationResult,
    DemoOrganizationBootstrapResponse,
    SharedIntelPayload,
    SharedIntelSearchRequest,
    SharedIntelSearchResponse,
)
from app.security import (
    create_signed_api_key,
    hash_api_key,
    require_central_admin,
)

logger = logging.getLogger(__name__)


def _rebuild_shared_intel_faiss_index(application: FastAPI) -> bool:
    session_factory = getattr(application.state, "testing_session_factory", SessionLocal)
    db = session_factory()
    try:
        entries = (
            (record_id, embedding)
            for record_id, embedding in db.query(
                SharedIntel.id,
                SharedIntel.embedding,
            )
            .filter(SharedIntel.embedding.is_not(None))
            .order_by(SharedIntel.id)
            .yield_per(500)
        )
        return get_faiss_index().rebuild(entries)
    finally:
        db.close()


async def _faiss_rebuild_loop(application: FastAPI) -> None:
    while True:
        await asyncio.sleep(settings.FAISS_REBUILD_INTERVAL_SECONDS)
        try:
            await run_in_threadpool(
                _rebuild_shared_intel_faiss_index,
                application,
            )
        except Exception:
            logger.exception("Periodic SharedIntel FAISS rebuild failed")


@asynccontextmanager
async def lifespan(application: FastAPI):
    try:
        await run_in_threadpool(_rebuild_shared_intel_faiss_index, application)
    except Exception:
        logger.exception("Initial SharedIntel FAISS rebuild failed; pgvector remains available")
    rebuild_task = asyncio.create_task(_faiss_rebuild_loop(application))
    try:
        yield
    finally:
        rebuild_task.cancel()
        try:
            await rebuild_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Cyber Memory Network Central Server",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)


@app.get("/api/central/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/api/central/orgs/register",
    response_model=OrganizationRegistrationResult,
    status_code=status.HTTP_201_CREATED,
    tags=["organizations"],
    summary="Register an org-local Stage 1 deployment",
)
def register_organization(
    body: OrganizationRegistration,
    db: Session = Depends(get_db),
) -> OrganizationRegistrationResult:
    organization = Organization(
        name=body.name,
        contact_email=str(body.contact_email) if body.contact_email else None,
        api_key_hash=hash_api_key(secrets.token_urlsafe(32)),
    )
    db.add(organization)
    db.flush()

    api_key = create_signed_api_key(organization.id)
    organization.api_key_hash = hash_api_key(api_key)
    db.commit()
    db.refresh(organization)
    return OrganizationRegistrationResult(
        id=organization.id,
        name=organization.name,
        api_key=api_key,
        registered_at=organization.registered_at,
    )


@app.get(
    "/api/central/orgs",
    response_model=list[OrganizationListItem],
    tags=["organizations"],
    dependencies=[Depends(require_central_admin)],
    summary="List registered organizations (central admin only)",
)
def list_organizations(db: Session = Depends(get_db)) -> list[Organization]:
    return db.query(Organization).order_by(Organization.name, Organization.id).all()


@app.post(
    "/api/central/admin/demo-organizations",
    response_model=DemoOrganizationBootstrapResponse,
    tags=["organizations"],
    dependencies=[Depends(require_central_admin)],
    summary="Create or refresh the fixed demo organizations (central admin only)",
)
def bootstrap_demo_organizations(
    db: Session = Depends(get_db),
) -> DemoOrganizationBootstrapResponse:
    """Return one-time keys for the fixed local demo identities.

    Existing demo rows are reused and their keys rotated, so seed reruns do not
    create duplicate organizations. The endpoint is protected by the central
    admin token and is intended only for the demo seed workflow.
    """
    names = (
        "Demo Network Alpha",
        "Demo Network Beta",
        "Demo Network Gamma",
    )
    results = []
    for name in names:
        organization = (
            db.query(Organization)
            .filter(Organization.name == name)
            .order_by(Organization.id)
            .first()
        )
        if organization is None:
            organization = Organization(
                name=name,
                api_key_hash=hash_api_key(secrets.token_urlsafe(32)),
            )
            db.add(organization)
            db.flush()
        api_key = create_signed_api_key(organization.id)
        organization.api_key_hash = hash_api_key(api_key)
        organization.status = "active"
        results.append(
            {
                "id": organization.id,
                "name": organization.name,
                "api_key": api_key,
            }
        )
    db.commit()
    return DemoOrganizationBootstrapResponse(organizations=results)


@app.get(
    "/api/central/orgs/me",
    response_model=OrganizationIdentity,
    tags=["organizations"],
    summary="Validate the calling org's central registration",
)
def get_organization_identity(
    organization: Organization = Depends(get_current_org),
) -> Organization:
    return organization


@app.post(
    "/api/central/intel/submit",
    status_code=status.HTTP_201_CREATED,
    tags=["shared intelligence"],
    summary="Submit anonymized intelligence from an authenticated organization",
)
def submit_shared_intel(
    body: SharedIntelPayload,
    db: Session = Depends(get_db),
    organization: Organization = Depends(get_current_org),
) -> dict[str, int | bool]:
    canonical_payload = body.model_dump(mode="json")
    dedup_hash = hashlib.sha256(
        json.dumps(
            canonical_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()

    existing = (
        db.query(SharedIntel)
        .filter(
            SharedIntel.source_org_id == organization.id,
            SharedIntel.dedup_hash == dedup_hash,
        )
        .first()
    )
    if existing is not None:
        return {"id": existing.id, "duplicate": True}

    record = SharedIntel(
        source_org_id=organization.id,
        mitre_technique_ids=body.mitre_technique_ids,
        severity=body.severity,
        rule_categories=body.rule_categories,
        sanitized_text=body.sanitized_text,
        embedding=body.embedding,
        dedup_hash=dedup_hash,
    )
    db.add(record)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(SharedIntel)
            .filter(
                SharedIntel.source_org_id == organization.id,
                SharedIntel.dedup_hash == dedup_hash,
            )
            .first()
        )
        if existing is None:
            raise
        return {"id": existing.id, "duplicate": True}
    db.refresh(record)
    if record.embedding is not None:
        try:
            get_faiss_index().add(record.id, record.embedding)
        except Exception:
            logger.exception("Could not add SharedIntel %s to FAISS index", record.id)
    return {"id": record.id, "duplicate": False}


@app.get(
    "/api/central/intel/stats",
    tags=["shared intelligence"],
    dependencies=[Depends(require_central_admin)],
    summary="Get central intelligence aggregates (central admin only)",
)
def shared_intel_stats(db: Session = Depends(get_db)) -> dict:
    records = db.query(SharedIntel.mitre_technique_ids, SharedIntel.severity).all()
    techniques: dict[str, int] = {}
    severities: dict[str, int] = {}
    for technique_ids, severity_values in records:
        for technique_id in set(technique_ids or []):
            techniques[technique_id] = techniques.get(technique_id, 0) + 1
        for severity_value in set(severity_values or []):
            severities[severity_value] = severities.get(severity_value, 0) + 1

    return {
        "total": len(records),
        "by_technique": [
            {"technique_id": key, "count": count}
            for key, count in sorted(techniques.items())
        ],
        "by_severity": [
            {"severity": key, "count": count}
            for key, count in sorted(severities.items())
        ],
    }


def _search_shared_intel_faiss(
    db: Session,
    body: SharedIntelSearchRequest,
    organization: Organization,
) -> SharedIntelSearchResponse | None:
    index = get_faiss_index()
    indexed_count = index.count
    if not index.available or not indexed_count:
        return None
    try:
        candidate_count = min(indexed_count, max(body.top_k * 4, body.top_k))
        query_norm = math.sqrt(sum(value * value for value in body.embedding))
        while True:
            candidates = index.search(body.embedding, candidate_count)
            if candidates is None:
                return None
            candidate_ids = [item_id for item_id, _score in candidates]
            records = (
                db.query(SharedIntel)
                .filter(
                    SharedIntel.id.in_(candidate_ids),
                    SharedIntel.embedding.is_not(None),
                    SharedIntel.source_org_id != organization.id,
                )
                .all()
            )
            by_id = {record.id: record for record in records}
            ranked: list[tuple[SharedIntel, float]] = []
            for record_id, _faiss_score in candidates:
                record = by_id.get(record_id)
                if record is None:
                    continue
                vector = record.embedding
                if isinstance(vector, str):
                    try:
                        vector = json.loads(vector)
                    except (TypeError, ValueError):
                        continue
                if not isinstance(vector, (list, tuple)) or len(vector) != len(body.embedding):
                    continue
                vector_values = [float(value) for value in vector]
                vector_norm = math.sqrt(sum(value * value for value in vector_values))
                similarity = (
                    sum(left * right for left, right in zip(body.embedding, vector_values))
                    / (query_norm * vector_norm)
                    if query_norm and vector_norm
                    else 0.0
                )
                ranked.append((record, similarity))
            ranked.sort(key=lambda item: item[1], reverse=True)
            if len(ranked) >= body.top_k or candidate_count >= indexed_count:
                matches = ranked[: body.top_k]
                return SharedIntelSearchResponse(
                    results=[
                        {
                            "sanitized_text": record.sanitized_text,
                            "mitre_technique_ids": record.mitre_technique_ids or [],
                            "severity": record.severity or [],
                            "similarity_score": round(float(score), 4),
                        }
                        for record, score in matches
                    ],
                    total_found=len(matches),
                )
            candidate_count = min(indexed_count, candidate_count * 2)
    except Exception:
        logger.exception("FAISS SharedIntel search failed; falling back to pgvector")
        return None


@app.post(
    "/api/central/intel/search",
    response_model=SharedIntelSearchResponse,
    tags=["shared intelligence"],
    summary="Search anonymized cross-organization intelligence",
)
def search_shared_intel(
    body: SharedIntelSearchRequest,
    db: Session = Depends(get_db),
    organization: Organization = Depends(get_current_org),
) -> SharedIntelSearchResponse:
    if (
        not settings.CENTRAL_ALLOW_READ_WITHOUT_CONTRIBUTION
        and not db.query(SharedIntel.id)
        .filter(SharedIntel.source_org_id == organization.id)
        .first()
    ):
        raise HTTPException(
            status_code=403,
            detail="Central network search requires sharing opt-in",
        )

    faiss_results = _search_shared_intel_faiss(db, body, organization)
    if faiss_results is not None and faiss_results.total_found:
        return faiss_results

    if db.bind is not None and db.bind.dialect.name == "sqlite":
        rows = (
            db.query(SharedIntel)
            .filter(
                SharedIntel.embedding.is_not(None),
                SharedIntel.source_org_id != organization.id,
            )
            .all()
        )
        ranked = []
        query_norm = math.sqrt(sum(value * value for value in body.embedding))
        for record in rows:
            vector = record.embedding
            if isinstance(vector, str):
                vector = json.loads(vector)
            if not isinstance(vector, (list, tuple)) or len(vector) != len(body.embedding):
                continue
            dot = sum(left * right for left, right in zip(body.embedding, vector))
            vector_norm = math.sqrt(sum(value * value for value in vector))
            similarity = (
                dot / (query_norm * vector_norm)
                if query_norm and vector_norm
                else 0.0
            )
            ranked.append((record, similarity))
        ranked.sort(key=lambda item: item[1], reverse=True)
        matches = ranked[: body.top_k]
    else:
        vector_literal = "[" + ",".join(f"{value:.8f}" for value in body.embedding) + "]"
        query = text(
            """
            SELECT
                sanitized_text,
                mitre_technique_ids,
                severity,
                1 - (embedding <=> CAST(:embedding AS vector)) AS similarity_score
            FROM shared_intel
            WHERE embedding IS NOT NULL
              AND source_org_id != :source_org_id
            ORDER BY embedding <=> CAST(:embedding AS vector) ASC
            LIMIT :top_k
            """
        )
        try:
            rows = db.execute(
                query,
                {
                    "embedding": vector_literal,
                    "top_k": body.top_k,
                    "source_org_id": organization.id,
                },
            ).fetchall()
        except Exception:
            logger.exception("Central pgvector search failed")
            raise
        return SharedIntelSearchResponse(
            results=[
                {
                    "sanitized_text": row.sanitized_text,
                    "mitre_technique_ids": row.mitre_technique_ids or [],
                    "severity": row.severity or [],
                    "similarity_score": round(float(row.similarity_score), 4),
                }
                for row in rows
            ],
            total_found=len(rows),
        )

    return SharedIntelSearchResponse(
        results=[
            {
                "sanitized_text": record.sanitized_text,
                "mitre_technique_ids": record.mitre_technique_ids or [],
                "severity": record.severity or [],
                "similarity_score": round(float(score), 4),
            }
            for record, score in matches
        ],
        total_found=len(matches),
    )
