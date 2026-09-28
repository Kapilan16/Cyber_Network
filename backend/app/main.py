"""
Cyber Network – Backend
FastAPI application factory and root router.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.v1.router import api_router


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Application lifespan events (startup / shutdown)."""
    # Future: initialise DB connection pool, ML models, etc.
    yield
    # Future: graceful teardown


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
