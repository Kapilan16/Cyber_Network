"""Rate-limited, read-only HTTPS clients for VirusTotal and AbuseIPDB."""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class EnrichmentError(RuntimeError):
    """A provider request could not complete successfully."""


class MissingAPIKeyError(EnrichmentError):
    """The requested provider has no configured API key."""


@dataclass(frozen=True)
class EnrichmentResponse:
    reputation_score: int | None
    raw_response_summary: dict


class ProviderRateLimiter:
    """Serialize requests per provider and enforce a minimum request interval."""

    def __init__(
        self,
        intervals: dict[str, float],
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._intervals = intervals
        self._sleep = sleep
        self._clock = clock
        self._locks = {provider: threading.Lock() for provider in intervals}
        self._last_request: dict[str, float] = {}

    def wait(self, provider: str) -> None:
        lock = self._locks[provider]
        with lock:
            now = self._clock()
            wait_seconds = self._intervals[provider] - (
                now - self._last_request.get(provider, float("-inf"))
            )
            if wait_seconds > 0:
                self._sleep(wait_seconds)
            self._last_request[provider] = self._clock()


_rate_limiter = ProviderRateLimiter(
    {
        "virustotal": settings.VIRUSTOTAL_MIN_INTERVAL_SECONDS,
        "abuseipdb": settings.ABUSEIPDB_MIN_INTERVAL_SECONDS,
    }
)


class ThreatIntelClient:
    """Perform read-only IOC lookups; no endpoint initiates active scanning."""

    def __init__(
        self,
        *,
        virustotal_api_key: str | None = None,
        abuseipdb_api_key: str | None = None,
        transport: httpx.BaseTransport | None = None,
        rate_limiter: ProviderRateLimiter | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._virustotal_api_key = (
            settings.VIRUSTOTAL_API_KEY
            if virustotal_api_key is None
            else virustotal_api_key
        )
        self._abuseipdb_api_key = (
            settings.ABUSEIPDB_API_KEY
            if abuseipdb_api_key is None
            else abuseipdb_api_key
        )
        self._transport = transport
        self._rate_limiter = rate_limiter or _rate_limiter
        self._sleep = sleep

    def query(self, source: str, ioc_type: str, ioc_value: str) -> EnrichmentResponse:
        if source == "virustotal":
            return self._query_virustotal(ioc_type, ioc_value)
        if source == "abuseipdb":
            if ioc_type != "ip":
                raise EnrichmentError("AbuseIPDB supports IP addresses only")
            return self._query_abuseipdb(ioc_value)
        raise EnrichmentError("Unsupported enrichment provider")

    def _query_virustotal(self, ioc_type: str, value: str) -> EnrichmentResponse:
        if not self._virustotal_api_key:
            raise MissingAPIKeyError("VIRUSTOTAL_API_KEY is not configured")
        path_by_type = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files",
        }
        resource = path_by_type.get(ioc_type)
        if resource is None:
            raise EnrichmentError("Unsupported VirusTotal IOC type")
        url = f"https://www.virustotal.com/api/v3/{resource}/{quote(value, safe='')}"
        payload = self._request(
            "virustotal",
            "GET",
            url,
            headers={"x-apikey": self._virustotal_api_key},
        )
        try:
            attributes = payload["data"]["attributes"]
            stats = attributes.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(
                int(stats.get(key, 0))
                for key in ("malicious", "suspicious", "harmless", "undetected")
            )
            score = round(100 * (malicious + suspicious) / total) if total else None
            summary = {
                "last_analysis_stats": {
                    key: int(stats.get(key, 0))
                    for key in ("malicious", "suspicious", "harmless", "undetected")
                },
                "reputation": int(attributes.get("reputation", 0)),
                "last_analysis_date": attributes.get("last_analysis_date"),
            }
            return EnrichmentResponse(score, summary)
        except (KeyError, TypeError, ValueError) as exc:
            raise EnrichmentError("VirusTotal returned an unexpected response") from exc

    def _query_abuseipdb(self, value: str) -> EnrichmentResponse:
        if not self._abuseipdb_api_key:
            raise MissingAPIKeyError("ABUSEIPDB_API_KEY is not configured")
        payload = self._request(
            "abuseipdb",
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": self._abuseipdb_api_key,
                "Accept": "application/json",
            },
            params={"ipAddress": value, "maxAgeInDays": "90"},
        )
        try:
            data = payload["data"]
            score = int(data["abuseConfidenceScore"])
            summary = {
                "abuseConfidenceScore": score,
                "totalReports": int(data.get("totalReports", 0)),
                "numDistinctUsers": int(data.get("numDistinctUsers", 0)),
                "countryCode": data.get("countryCode"),
            }
            return EnrichmentResponse(score, summary)
        except (KeyError, TypeError, ValueError) as exc:
            raise EnrichmentError("AbuseIPDB returned an unexpected response") from exc

    def _request(
        self,
        provider: str,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
    ) -> dict:
        last_error: Exception | None = None
        for attempt in range(settings.ENRICHMENT_MAX_RETRIES + 1):
            self._rate_limiter.wait(provider)
            try:
                with httpx.Client(
                    timeout=settings.ENRICHMENT_TIMEOUT_SECONDS,
                    transport=self._transport,
                ) as http:
                    response = http.request(
                        method,
                        url,
                        headers=headers,
                        params=params,
                    )
                if response.status_code == 429 or response.status_code >= 500:
                    if attempt < settings.ENRICHMENT_MAX_RETRIES:
                        retry_after = response.headers.get("Retry-After")
                        delay = (
                            min(float(retry_after), 60.0)
                            if retry_after and retry_after.isdigit()
                            else 2**attempt
                        )
                        self._sleep(delay)
                        continue
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise EnrichmentError("Threat-intelligence provider returned invalid JSON")
                return payload
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = exc
                if attempt < settings.ENRICHMENT_MAX_RETRIES:
                    self._sleep(2**attempt)
                    continue
                break
            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                raise EnrichmentError(
                    f"Threat-intelligence provider returned HTTP {status_code}"
                ) from exc
            except ValueError as exc:
                raise EnrichmentError("Threat-intelligence provider returned invalid JSON") from exc

        raise EnrichmentError("Threat-intelligence provider request failed") from last_error
