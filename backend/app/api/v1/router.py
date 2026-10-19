"""Root v1 API router — aggregates all sub-routers."""
from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    analytics,
    dashboard,
    health,
    memory,
    mitre,
    network,
    rules,
    search,
    submissions,
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(submissions.router, prefix="/submissions", tags=["submissions"])
api_router.include_router(rules.router, tags=["rules"])
api_router.include_router(mitre.router)         # prefix="/mitre" set on the router itself
api_router.include_router(search.router)        # prefix="/search" set on the router itself
api_router.include_router(dashboard.router)     # prefix="/dashboard" set on the router itself
api_router.include_router(memory.router)        # prefix="/memory" set on the router itself
api_router.include_router(network.router)
api_router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
