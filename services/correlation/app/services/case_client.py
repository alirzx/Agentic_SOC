"""HTTP client for ``POST /api/v1/cases/from-correlation`` (doc §7.2).

The correlation engine never writes ``aisoc_cases`` directly. Case creation,
the state machine, tenant scoping and the dedup filter all live behind the API
so there is exactly one writer for the canonical case row. This client is the
only path the engine has to it.

Failures are surfaced, never swallowed into a "case created" log line: if the
API rejects the bundle the engine marks the alerts ``correlation_state='error'``
so the next cycle retries them instead of leaving evidence orphaned.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class CaseClientError(RuntimeError):
    """Raised when the API refuses or cannot persist a correlated case."""


class CaseClient:
    def __init__(
        self,
        *,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self._base = (base_url or settings.api_service_url).rstrip("/")
        self._token = settings.correlation_api_token if token is None else token
        self._timeout = timeout or settings.api_timeout_seconds
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> CaseClient:
        # Create client with explicit connection pool config to prevent buffer exhaustion
        self._client = httpx.AsyncClient(
            base_url=self._base,
            timeout=self._timeout,
            headers=self._headers(),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def create_from_correlation(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create or extend the case for one correlated component."""
        if self._client is None:
            raise CaseClientError("client not initialized; use 'async with CaseClient() as client:'")
        response = await self._client.post("/api/v1/cases/from-correlation", json=payload)
        if response.status_code >= 400:
            detail = response.text[:500]
            raise CaseClientError(f"HTTP {response.status_code}: {detail}")
        body = response.json()
        logger.info(
            "case_client.created",
            case_id=body.get("id"),
            created=body.get("created"),
            alerts=len(payload.get("related_alert_ids") or []),
            campaign_key=payload.get("campaign_key"),
        )
        return body


__all__ = ["CaseClient", "CaseClientError"]
