"""Splunk REST API client — read-only search jobs (Phase 8.7)."""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from .config import SplunkConfig
from .errors import (
    SplunkAuthenticationError,
    SplunkAuthorizationError,
    SplunkError,
    SplunkQueryError,
    SplunkTimeoutError,
    SplunkUnavailableError,
)
from .metrics import record_splunk_metric

logger = structlog.get_logger()


class SplunkClient:
    """Read-only Splunk REST client using Basic Authentication."""

    def __init__(self, config: SplunkConfig) -> None:
        self._config = config
        self._base = config.base_url.rstrip("/")

    def _auth(self) -> tuple[str, str] | None:
        if self._config.username and self._config.password:
            return (self._config.username, self._config.password)
        return None

    async def health_check(self) -> dict[str, object]:
        if not self._config.enabled:
            return {"status": "DISABLED", "host": self._config.host, "port": self._config.port}
        if not self._config.base_url or not self._auth():
            return {"status": "CONFIGURATION_ERROR", "host": self._config.host, "port": self._config.port}
        try:
            data = await self._request("GET", "/services/server/info", params={"output_mode": "json"})
            record_splunk_metric("splunk_success_total")
            return {
                "status": "HEALTHY",
                "host": self._config.host,
                "port": self._config.port,
                "version": _extract_version(data),
            }
        except SplunkAuthenticationError:
            record_splunk_metric("splunk_auth_failures_total")
            return {"status": "SPLUNK_AUTH_FAILURE", "host": self._config.host, "port": self._config.port}
        except SplunkError as exc:
            return {"status": exc.status, "host": self._config.host, "port": self._config.port}

    async def search(
        self,
        query: str,
        *,
        earliest: str | None = None,
        latest: str | None = "now",
        max_events: int | None = None,
    ) -> tuple[str, list[dict[str, Any]], int]:
        """Create search job, poll to completion, return (sid, rows, duration_ms)."""
        started = time.monotonic()
        limit = min(max_events or self._config.max_events_per_query, self._config.max_events_per_query)
        sid = await self._create_job(query, earliest=earliest, latest=latest)
        await self._poll_until_done(sid)
        rows = await self._fetch_results(sid, limit=limit + 1)
        duration_ms = int((time.monotonic() - started) * 1000)
        record_splunk_metric("splunk_events_returned_total", value=min(len(rows), limit))
        record_splunk_metric("splunk_query_duration", value=duration_ms)
        return sid, rows[:limit], duration_ms

    async def _create_job(self, query: str, *, earliest: str | None, latest: str | None) -> str:
        data = {
            "search": query,
            "exec_mode": "normal",
            "output_mode": "json",
            "earliest_time": earliest or f"-{self._config.max_query_window_minutes}m",
            "latest_time": latest or "now",
        }
        payload = await self._request("POST", "/services/search/jobs", data=data)
        sid = _extract_sid(payload)
        if not sid:
            raise SplunkQueryError("Splunk did not return a search job id")
        return sid

    async def _poll_until_done(self, sid: str) -> None:
        deadline = time.monotonic() + self._config.max_poll_seconds
        while time.monotonic() < deadline:
            payload = await self._request("GET", f"/services/search/jobs/{quote(sid, safe='')}", params={"output_mode": "json"})
            if _job_is_done(payload):
                return
            await asyncio.sleep(self._config.poll_interval_seconds)
        record_splunk_metric("splunk_timeouts_total")
        raise SplunkTimeoutError("Splunk search job polling timed out")

    async def _fetch_results(self, sid: str, *, limit: int) -> list[dict[str, Any]]:
        payload = await self._request(
            "GET",
            f"/services/search/jobs/{quote(sid, safe='')}/results",
            params={"output_mode": "json", "count": str(limit)},
        )
        if isinstance(payload, dict):
            results = payload.get("results")
            if isinstance(results, list):
                return [row for row in results if isinstance(row, dict)]
        return []

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        retry: bool = True,
    ) -> Any:
        record_splunk_metric("splunk_requests_total")
        url = f"{self._base}{path}"
        auth = self._auth()
        if auth is None:
            raise SplunkUnavailableError("Splunk credentials are not configured")
        try:
            return await self._do_request(method, url, auth=auth, params=params, data=data)
        except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
            if retry:
                return await self._request(method, path, params=params, data=data, retry=False)
            raise SplunkTimeoutError(str(exc)) from exc
        except httpx.HTTPStatusError as exc:
            if retry and exc.response.status_code >= 500:
                return await self._request(method, path, params=params, data=data, retry=False)
            raise _map_http_error(exc) from exc

    async def _do_request(
        self,
        method: str,
        url: str,
        *,
        auth: tuple[str, str],
        params: dict[str, str] | None,
        data: dict[str, str] | None,
    ) -> Any:
        async with httpx.AsyncClient(timeout=self._config.timeout_seconds, verify=self._config.verify_ssl) as client:
            if method == "GET":
                response = await client.get(url, auth=auth, params=params)
            else:
                response = await client.post(
                    url,
                    auth=auth,
                    params=params,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            response.raise_for_status()
            return response.json()


def _map_http_error(exc: httpx.HTTPStatusError) -> SplunkError:
    status = exc.response.status_code
    if status == 401:
        return SplunkAuthenticationError("Splunk authentication failed", http_status=status)
    if status == 403:
        return SplunkAuthorizationError("Splunk authorization failed", http_status=status)
    if status == 400:
        record_splunk_metric("splunk_query_rejected_total")
        return SplunkQueryError("Splunk rejected the query", http_status=status)
    if status >= 500:
        record_splunk_metric("splunk_query_errors_total")
        return SplunkUnavailableError(f"Splunk server error ({status})", http_status=status)
    record_splunk_metric("splunk_query_errors_total")
    return SplunkQueryError(f"Splunk HTTP error ({status})", http_status=status)


def _extract_sid(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    sid = payload.get("sid")
    if isinstance(sid, str) and sid:
        return sid
    entry = payload.get("entry")
    if isinstance(entry, list) and entry:
        content = entry[0].get("content") if isinstance(entry[0], dict) else None
        if isinstance(content, dict):
            sid_val = content.get("sid")
            return str(sid_val) if sid_val else None
    return None


def _job_is_done(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    entry = payload.get("entry")
    if isinstance(entry, list) and entry and isinstance(entry[0], dict):
        content = entry[0].get("content")
        if isinstance(content, dict):
            if content.get("isDone") in (True, "1", 1):
                return True
            if str(content.get("dispatchState", "")).upper() == "DONE":
                return True
    return False


def _extract_version(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    entry = payload.get("entry")
    if isinstance(entry, list) and entry and isinstance(entry[0], dict):
        content = entry[0].get("content")
        if isinstance(content, dict):
            version = content.get("version")
            return str(version) if version else None
    return None


def hash_query(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
