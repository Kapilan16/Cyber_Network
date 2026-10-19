"""Optional HTTP client for an org-local deployment's central registry connection."""
from __future__ import annotations

import time
from math import ceil
from typing import Any, Callable

import httpx

from app.core.config import settings


class CentralClientConfigurationError(RuntimeError):
    """Raised when central communication is requested without valid config."""


class CentralRequestError(RuntimeError):
    """Raised when the central server rejects a request or returns invalid data."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class CentralUnavailableError(RuntimeError):
    """Raised when the central service cannot be reached after bounded retries."""

    def __init__(self, message: str, attempts: int, retry_after_seconds: int = 0):
        super().__init__(message)
        self.attempts = attempts
        self.retry_after_seconds = retry_after_seconds


class CentralClient:
    """Bearer-authenticated client with retries and a per-instance circuit breaker."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._base_url = (
            base_url if base_url is not None else settings.CENTRAL_SERVER_URL
        ).strip()
        self._api_key = api_key if api_key is not None else settings.CENTRAL_API_KEY
        if not self._base_url or not self._api_key:
            raise CentralClientConfigurationError(
                "CENTRAL_SERVER_URL and CENTRAL_API_KEY must be set to use the central client"
            )
        if settings.ENVIRONMENT.lower() not in {"development", "dev", "test"} and not (
            self._base_url.lower().startswith("https://")
        ):
            raise CentralClientConfigurationError(
                "Central server communication requires HTTPS outside development"
            )

        self._max_retries = settings.CENTRAL_MAX_RETRIES
        self._backoff = settings.CENTRAL_RETRY_BACKOFF_SECONDS
        self._failure_threshold = settings.CENTRAL_CIRCUIT_FAILURE_THRESHOLD
        self._cooldown = settings.CENTRAL_CIRCUIT_COOLDOWN_SECONDS
        self._sleep = sleep
        self._clock = clock
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0
        self._http = httpx.Client(
            base_url=self._base_url.rstrip("/") + "/",
            headers={"Authorization": f"Bearer {self._api_key}"},
            timeout=settings.CENTRAL_TIMEOUT_SECONDS,
            transport=transport,
        )

    def get_org_info(self) -> dict[str, Any]:
        """Fetch the authenticated org identity without affecting local workflows."""
        return self._request_json("GET", "api/central/orgs/me")

    def submit_intel(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Submit one anonymized payload; central-side failures remain explicit."""
        return self._request_json("POST", "api/central/intel/submit", json=payload)

    def search_intel(
        self,
        embedding: list[float],
        top_k: int = 10,
    ) -> dict[str, Any]:
        """Search anonymized central incidents without exposing source org IDs."""
        return self._request_json(
            "POST",
            "api/central/intel/search",
            json={"embedding": embedding, "top_k": top_k},
        )

    def get_intel_stats(self) -> dict[str, Any]:
        """Fetch central aggregate statistics for opted-in network analytics."""
        return self._request_json(
            "GET",
            "api/central/intel/stats",
            headers={"X-Central-Admin-Token": settings.CENTRAL_ADMIN_TOKEN},
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> CentralClient:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        now = self._clock()
        if now < self._circuit_open_until:
            retry_after = max(1, ceil(self._circuit_open_until - now))
            raise CentralUnavailableError(
                "Central circuit breaker is open",
                attempts=0,
                retry_after_seconds=retry_after,
            )

        last_error: Exception | None = None
        attempts = 0
        for attempt in range(self._max_retries + 1):
            attempts += 1
            try:
                response = self._http.request(
                    method,
                    path,
                    json=json,
                    headers=headers,
                )
                if response.status_code >= 500:
                    last_error = httpx.HTTPStatusError(
                        f"Central server returned HTTP {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                else:
                    try:
                        response.raise_for_status()
                    except httpx.HTTPStatusError as exc:
                        raise CentralRequestError(
                            f"Central server rejected request with HTTP {response.status_code}",
                            status_code=response.status_code,
                        ) from exc
                    try:
                        payload = response.json()
                    except ValueError as exc:
                        raise CentralRequestError(
                            "Central server returned invalid JSON",
                            status_code=response.status_code,
                        ) from exc
                    if not isinstance(payload, dict):
                        raise CentralRequestError(
                            "Central server returned an unexpected response shape",
                            status_code=response.status_code,
                        )
                    self._consecutive_failures = 0
                    self._circuit_open_until = 0.0
                    return payload
            except httpx.RequestError as exc:
                last_error = exc

            if attempt < self._max_retries:
                self._sleep(self._backoff * (2**attempt))

        self._consecutive_failures += 1
        if self._consecutive_failures >= self._failure_threshold:
            self._circuit_open_until = self._clock() + self._cooldown
        retry_after = (
            max(1, ceil(self._circuit_open_until - self._clock()))
            if self._circuit_open_until
            else 0
        )
        error_name = type(last_error).__name__ if last_error else "unknown error"
        raise CentralUnavailableError(
            f"Central server unavailable after {attempts} attempt(s): {error_name}",
            attempts=attempts,
            retry_after_seconds=retry_after,
        ) from last_error
