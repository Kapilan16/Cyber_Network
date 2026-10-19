"""Central API authentication and per-organization rate limiting."""
import threading
import time
from collections import defaultdict, deque
from math import ceil

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import Organization, OrganizationStatus
from app.security import hash_api_key, verify_api_key_signature

bearer_scheme = HTTPBearer(auto_error=False)


class OrganizationRateLimiter:
    """Thread-safe per-process sliding-window limiter, keyed by organization."""

    def __init__(self) -> None:
        self._events: dict[int, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._cleanup_requests = 0

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
            self._cleanup_requests = 0

    def enforce(self, organization_id: int) -> None:
        now = time.monotonic()
        window = settings.CENTRAL_RATE_LIMIT_WINDOW_SECONDS
        limit = settings.CENTRAL_RATE_LIMIT_REQUESTS
        cutoff = now - window

        with self._lock:
            self._cleanup_requests += 1
            if self._cleanup_requests >= 128:
                for org_id in list(self._events):
                    org_events = self._events[org_id]
                    while org_events and org_events[0] <= cutoff:
                        org_events.popleft()
                    if not org_events:
                        del self._events[org_id]
                self._cleanup_requests = 0

            events = self._events[organization_id]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, ceil(events[0] + window - now))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Organization rate limit exceeded",
                    headers={"Retry-After": str(retry_after)},
                )
            events.append(now)


rate_limiter = OrganizationRateLimiter()


def get_current_org(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Organization:
    """Validate a signed bearer key, active status, and organization quota."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer organization API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    api_key = credentials.credentials
    if not verify_api_key_signature(api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid organization API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    organization = (
        db.query(Organization)
        .filter(Organization.api_key_hash == hash_api_key(api_key))
        .first()
    )
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid organization API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if organization.status != OrganizationStatus.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization is suspended",
        )

    rate_limiter.enforce(organization.id)
    return organization
