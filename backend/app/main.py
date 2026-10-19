"""
Cyber Network – Backend
FastAPI application factory and root router.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

from app.core.config import settings
from app.api.v1.router import api_router
from app.core.database import SessionLocal

logger = logging.getLogger(__name__)


async def _campaign_scan_loop() -> None:
    """Periodically recalculate recurring and dormant memory-node flags."""
    from app.correlation.campaigns import scan_recurring_memory_nodes_background

    while True:
        await asyncio.sleep(settings.CAMPAIGN_SCAN_INTERVAL_SECONDS)
        try:
            await run_in_threadpool(scan_recurring_memory_nodes_background)
        except Exception:
            logger.exception("Periodic campaign scan failed; it will retry next interval")


def _rebuild_submission_faiss_index(application: FastAPI) -> bool:
    from app.models.raw_submission import EmbeddingStatus, RawSubmission
    from app.search.faiss_index import get_faiss_index

    session_factory = getattr(application.state, "testing_session_factory", SessionLocal)
    db = session_factory()
    try:
        entries = (
            (submission_id, embedding)
            for submission_id, embedding in db.query(
                RawSubmission.id,
                RawSubmission.embedding,
            )
            .filter(
                RawSubmission.embedding.is_not(None),
                RawSubmission.embedding_status == EmbeddingStatus.complete,
            )
            .order_by(RawSubmission.id)
            .yield_per(500)
        )
        return get_faiss_index().rebuild(entries)
    finally:
        db.close()


async def _faiss_rebuild_loop(application: FastAPI) -> None:
    while True:
        await asyncio.sleep(settings.FAISS_REBUILD_INTERVAL_SECONDS)
        try:
            await run_in_threadpool(_rebuild_submission_faiss_index, application)
        except Exception:
            logger.exception("Periodic submission FAISS rebuild failed")


async def _early_warning_scan_loop() -> None:
    from app.analytics.warnings import scan_early_warnings_background

    while True:
        await asyncio.sleep(settings.WARNING_SCAN_INTERVAL_SECONDS)
        try:
            await run_in_threadpool(scan_early_warnings_background)
        except Exception:
            logger.exception("Periodic early-warning scan failed; it will retry next interval")


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Application lifespan events (startup / shutdown)."""
    from app.embeddings.client import get_embeddings_client

    await run_in_threadpool(get_embeddings_client().initialize)
    try:
        await run_in_threadpool(_rebuild_submission_faiss_index, application)
    except Exception:
        logger.exception("Initial submission FAISS rebuild failed; pgvector remains available")
    scan_task = asyncio.create_task(_campaign_scan_loop())
    faiss_task = asyncio.create_task(_faiss_rebuild_loop(application))
    warning_task = asyncio.create_task(_early_warning_scan_loop())
    try:
        yield
    finally:
        scan_task.cancel()
        faiss_task.cancel()
        warning_task.cancel()
        try:
            await scan_task
        except asyncio.CancelledError:
            pass
        try:
            await faiss_task
        except asyncio.CancelledError:
            pass
        try:
            await warning_task
        except asyncio.CancelledError:
            pass


def create_app() -> FastAPI:
    application = FastAPI(
        title="Cyber Network API",
        version="0.1.0",
        description="Cybersecurity data-reasoning platform — scaffolding milestone.",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # ── CORS ────────────────────────────────────────────────────────────────
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ─────────────────────────────────────────────────────────────
    application.include_router(api_router, prefix="/api")

    return application


app = create_app()
