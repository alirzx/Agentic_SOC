"""
Splunk connector.
Runs saved searches, custom SPL, or fetches notable events from Splunk SIEM.
Supports Bearer token or Basic (username/password) auth.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field
from app.federated.query import UnifiedQuery
from app.federated.translators import to_spl

logger = structlog.get_logger()

# Page size for the results endpoint. ``head 100`` / ``count=100`` used to cap a
# poll at 100 notables and silently drop the rest (#529); we now page through
# every result. _MAX_PAGES bounds a single poll so a misconfigured saved search
# can't spin forever.
_DEFAULT_PAGE_SIZE = 500
_MAX_PAGES = 200
_JOB_POLL_ATTEMPTS = 30
_JOB_POLL_INTERVAL_S = 2.0
_SEVERITY_BY_URGENCY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
    # Enterprise Security notable param.severity is often 1–5.
    "1": "info",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "critical",
}

# Default SPL used when the operator pastes the ES correlation-search catalog
# query (lists notable *definitions*). Prefer ``| rest`` (not ``search rest``).
_DEFAULT_ES_CATALOG_SPL = (
    "| rest splunk_server=local count=0 /services/saved/searches "
    "| search action.correlationsearch.enabled=1 "
    "| eval notable_name=title "
    "| eval severity=action.notable.param.severity "
    "| eval annotations=action.correlationsearch.annotations "
    '| table notable_name description search annotations severity '
    '| rename notable_name as "Notable Name", '
    'description as "Description", '
    'search as "Notable SPL", '
    'severity as "Severity" '
    '| sort "Notable Name"'
)


def _map_severity(raw: Any) -> str:
    key = str(raw if raw is not None else "medium").strip().lower()
    return _SEVERITY_BY_URGENCY.get(key, "medium")


class SplunkConnector(BaseConnector):
    connector_id = "splunk"
    connector_name = "Splunk SIEM"
    connector_category = "siem"
    supports_federated_search = True

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Splunk Enterprise / Cloud notables via REST (token or basic auth).",
            docs_url="/docs/connectors/splunk",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Splunk URL",
                    placeholder="https://splunk.example.com:8089",
                    help_text="Management port (default 8089), not the web UI port (8000).",
                ),
                Field(
                    "token",
                    "secret",
                    "HEC / API Token (optional)",
                    required=False,
                    help_text="Bearer token. Leave blank when using username/password.",
                ),
                Field(
                    "username",
                    "string",
                    "Username",
                    required=False,
                    help_text="Basic auth username (e.g. admin). Used when token is empty.",
                ),
                Field(
                    "password",
                    "secret",
                    "Password",
                    required=False,
                    help_text="Basic auth password. Used when token is empty.",
                ),
                Field(
                    "saved_search",
                    "string",
                    "Saved Search Name",
                    required=False,
                    default="",
                    help_text="Dispatch a named saved search. Ignored when custom_search is set.",
                ),
                Field(
                    "custom_search",
                    "textarea",
                    "Custom SPL",
                    required=False,
                    default="",
                    help_text=(
                        "Ad-hoc SPL posted to /services/search/jobs. "
                        "When set, overrides saved_search / index=notable. "
                        "Use for ES correlation-search catalog or index=notable."
                    ),
                ),
                Field(
                    "earliest_time",
                    "string",
                    "Earliest time",
                    required=False,
                    default="-90d@d",
                    help_text="Splunk earliest_time for custom/saved dispatch (e.g. -90d@d, -24h).",
                ),
                Field(
                    "page_size",
                    "number",
                    "Results page size",
                    required=False,
                    default=_DEFAULT_PAGE_SIZE,
                    help_text="Number of results fetched per page. Polling pages through all results.",
                ),
                Field(
                    "ssl_verify",
                    "boolean",
                    "Verify SSL certificate",
                    required=False,
                    default=False,
                    help_text="Disable only for self-signed certificates in private deployments.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.SEARCH_SIEM,
            Capability.CREATE_NOTABLE_EVENT,
        )

    def __init__(
        self,
        base_url: str,
        token: str = "",
        username: str = "",
        password: str = "",
        saved_search: str = "",
        custom_search: str = "",
        earliest_time: str = "-90d@d",
        ssl_verify: bool = True,
        page_size: int = _DEFAULT_PAGE_SIZE,
        **_ignored: Any,
    ):
        self._base_url = base_url.rstrip("/")
        self._token = (token or "").strip()
        self._username = (username or "").strip()
        self._password = password or ""
        self._saved_search = (saved_search or "").strip()
        self._custom_search = (custom_search or "").strip()
        self._earliest_time = (earliest_time or "").strip() or "-90d@d"
        self._ssl_verify = ssl_verify
        try:
            self._page_size = max(1, int(page_size))
        except (TypeError, ValueError):
            self._page_size = _DEFAULT_PAGE_SIZE
        self._checkpoint: dict[str, str] | None = None
        self._next_checkpoint: dict[str, str] | None = None

    def set_checkpoint(self, checkpoint: dict[str, Any] | None) -> None:
        """Seed the poll with the last-accepted checkpoint (scheduler-owned)."""
        if isinstance(checkpoint, dict) and (checkpoint.get("time") or checkpoint.get("id")):
            self._checkpoint = {"time": str(checkpoint.get("time") or ""), "id": str(checkpoint.get("id") or "")}
        else:
            self._checkpoint = None

    def get_checkpoint(self) -> dict[str, str] | None:
        """Return the advanced checkpoint after a fetch, or None if unchanged."""
        return self._next_checkpoint

    def _auth(self) -> tuple[str, str] | None:
        if self._username and self._password:
            return (self._username, self._password)
        return None

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self._token and not self._auth():
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _client_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"timeout": 60.0, "verify": self._ssl_verify}
        auth = self._auth()
        if auth:
            kwargs["auth"] = auth
        return kwargs

    async def test_connection(self) -> dict[str, Any]:
        if not self._token and not self._auth():
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "Provide a token or username/password",
            }
        async with httpx.AsyncClient(**self._client_kwargs()) as client:
            try:
                resp = await client.get(
                    f"{self._base_url}/services/server/info",
                    headers=self._headers(),
                    params={"output_mode": "json"},
                )
                resp.raise_for_status()
                version = resp.json().get("entry", [{}])[0].get("content", {}).get("version")
                return {"success": True, "connector": self.connector_id, "version": version}
            except Exception as exc:
                logger.warning("splunk.test_connection.failed", error_type=type(exc).__name__)
                return {"success": False, "connector": self.connector_id, "error": "Connection failed"}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        earliest = self._earliest_time if self._custom_search else f"-{max(1, int(since_seconds))}s"
        async with httpx.AsyncClient(**self._client_kwargs()) as client:
            sid = await self._dispatch(client, earliest)
            if not sid:
                return []
            await self._await_job(client, sid)
            rows = await self._collect_results(client, sid)

        ordered = self._order_and_checkpoint(rows)
        return [self.normalize(r) for r in ordered]

    async def _dispatch(self, client: httpx.AsyncClient, earliest: str) -> str | None:
        """Kick off the search job and return its SID."""
        custom = self._custom_search
        if custom:
            search = custom if custom.lstrip().lower().startswith("search") else f"search {custom}"
            resp = await client.post(
                f"{self._base_url}/services/search/jobs",
                headers=self._headers(),
                data={
                    "search": search,
                    "earliest_time": earliest,
                    "latest_time": "now",
                    "output_mode": "json",
                },
            )
            resp.raise_for_status()
            return self._extract_sid(resp)

        ss = self._saved_search
        if ss and not ss.startswith("index="):
            resp = await client.post(
                f"{self._base_url}/services/saved/searches/{quote(ss, safe='')}/dispatch",
                headers=self._headers(),
                data={
                    "output_mode": "json",
                    "dispatch.earliest_time": earliest,
                    "dispatch.latest_time": "now",
                    "trigger_actions": "0",
                },
            )
            resp.raise_for_status()
            return self._extract_sid(resp)

        index = ss[len("index=") :] if ss.startswith("index=") else "notable"
        resp = await client.post(
            f"{self._base_url}/services/search/jobs",
            headers=self._headers(),
            data={"search": f"search index={index} earliest={earliest}", "output_mode": "json"},
        )
        resp.raise_for_status()
        return self._extract_sid(resp)

    @staticmethod
    def _extract_sid(resp: httpx.Response) -> str | None:
        try:
            data = resp.json()
            if isinstance(data, dict) and data.get("sid"):
                return str(data["sid"])
        except (ValueError, KeyError):
            pass
        match = re.search(r"<sid>([^<]+)</sid>", resp.text)
        return match.group(1) if match else None

    async def _await_job(self, client: httpx.AsyncClient, sid: str) -> str:
        for _ in range(_JOB_POLL_ATTEMPTS):
            resp = await client.get(
                f"{self._base_url}/services/search/jobs/{sid}",
                headers=self._headers(),
                params={"output_mode": "json"},
            )
            state = resp.json().get("entry", [{}])[0].get("content", {}).get("dispatchState", "")
            if state in ("DONE", "FAILED", "PAUSED"):
                return state
            await asyncio.sleep(_JOB_POLL_INTERVAL_S)
        return "TIMED_OUT"

    async def _collect_results(self, client: httpx.AsyncClient, sid: str) -> list[dict[str, Any]]:
        """Page through every result (#529) — no more silent ``head 100`` cap."""
        rows: list[dict[str, Any]] = []
        offset = 0
        for _ in range(_MAX_PAGES):
            resp = await client.get(
                f"{self._base_url}/services/search/jobs/{sid}/results",
                headers=self._headers(),
                params={"output_mode": "json", "count": self._page_size, "offset": offset},
            )
            resp.raise_for_status()
            page = resp.json().get("results", [])
            if not page:
                break
            rows.extend(page)
            if len(page) < self._page_size:
                break
            offset += len(page)
        return rows

    @staticmethod
    def _event_time(row: dict[str, Any]) -> str:
        return str(row.get("_time") or row.get("event_time") or "")

    @staticmethod
    def _event_tiebreak(row: dict[str, Any]) -> str:
        name = (
            row.get("event_id")
            or row.get("_cd")
            or row.get("Notable Name")
            or row.get("notable_name")
            or ""
        )
        return str(name)

    def _order_and_checkpoint(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ordered = sorted(rows, key=lambda r: (self._event_time(r), self._event_tiebreak(r)))
        # ES correlation catalog rows have no _time — emit the full snapshot every
        # poll and skip checkpoint filtering (otherwise only names after the last
        # alphabetically-sorted title would survive subsequent polls).
        if not any(self._event_time(r) for r in ordered):
            self._next_checkpoint = None
            return ordered
        cp = self._checkpoint or {}
        cp_key = (str(cp.get("time") or ""), str(cp.get("id") or ""))
        fresh: list[dict[str, Any]] = []
        for row in ordered:
            if cp_key[0] and (self._event_time(row), self._event_tiebreak(row)) <= cp_key:
                continue
            fresh.append(row)
        if fresh:
            last = fresh[-1]
            self._next_checkpoint = {"time": self._event_time(last), "id": self._event_tiebreak(last)}
        else:
            self._next_checkpoint = None
        return fresh

    async def query(self, unified: UnifiedQuery) -> list[dict[str, Any]]:
        """Run a translated SPL search and return raw rows."""
        index = self._saved_search if self._saved_search.startswith("index=") else "notable"
        spl = to_spl(unified, index=index)
        async with httpx.AsyncClient(**self._client_kwargs()) as client:
            resp = await client.post(
                f"{self._base_url}/services/search/jobs",
                headers=self._headers(),
                data={"search": spl, "output_mode": "json", "exec_mode": "oneshot"},
            )
            resp.raise_for_status()
            return list(resp.json().get("results", []))

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw, dict) and "raw_event" in raw and raw.get("source") == self.connector_id:
            return raw

        # ES correlation-search catalog rows (operator custom SPL).
        notable_name = raw.get("Notable Name") or raw.get("notable_name")
        if notable_name:
            title = str(notable_name)
            external_id = hashlib.sha256(title.encode("utf-8")).hexdigest()[:24]
            return {
                "source": self.connector_id,
                "external_id": external_id,
                "event_id": external_id,
                "title": title,
                "description": str(raw.get("Description") or raw.get("description") or ""),
                "severity": _map_severity(raw.get("Severity") or raw.get("severity")),
                "src_ip": None,
                "hostname": None,
                "raw_event": raw,
                "created_at": raw.get("_time"),
            }

        external_id = str(raw.get("event_id") or raw.get("_cd") or "")
        return {
            "source": self.connector_id,
            "external_id": external_id,
            "event_id": external_id,
            "title": raw.get("search_name") or raw.get("source") or "Splunk Notable Event",
            "description": raw.get("description", ""),
            "severity": _map_severity(raw.get("urgency") or raw.get("severity")),
            "src_ip": raw.get("src", raw.get("src_ip")),
            "hostname": raw.get("host"),
            "raw_event": raw,
            "created_at": raw.get("_time"),
        }
