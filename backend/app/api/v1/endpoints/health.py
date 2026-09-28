"""Health-check endpoint — GET /api/health."""
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    status: str


@router.get("/health", response_model=HealthResponse, summary="Health check")
async def health_check() -> HealthResponse:
    """Returns {\"status\": \"ok\"} when the service is running."""
    return HealthResponse(status="ok")
