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

# Default SPL used when the operator wants fired ES notables (incidents).
# Prefer this over the ``| rest`` correlation-search *catalog* (rule definitions).
# Time window is applied via ``earliest_time`` / poll cadence — do not embed
# ``earliest=`` in the SPL (it fights the connector's lookback).
_DEFAULT_NOTABLE_SPL = (
    "search index=notable "
    "| table _time source search_name severity urgency host dvc dest "
    "dest_port transport src src_ip source_guid source_event_id event_id _cd _raw"
)

# Default scheduler cadence for Splunk (30 minutes).
_DEFAULT_POLL_INTERVAL_SECONDS = 1800


def _map_severity(raw: Any) -> str:
    key = str(raw if raw is not None else "medium").strip().lower()
    return _SEVERITY_BY_URGENCY.get(key, "medium")


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """Accept real bools and common form/JSON string encodings."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off", ""}:
        return False
    return default


def _normalize_custom_spl(custom: str) -> str:
    """Prepare SPL for ``/services/search/jobs``.

    Generating commands (``| rest``, ``| inputlookup``, …) must not be
    prefixed with ``search``. Ad-hoc event searches without a leading
    ``search`` keyword still need it.
    """
    stripped = custom.strip()
    if not stripped:
        return stripped
    lower = stripped.lower()
    if lower.startswith("search ") or lower.startswith("|"):
        return stripped
    return f"search {stripped}"


_RAW_KV_RE = re.compile(r'([A-Za-z_][\w.]*)="([^"]*)"')


def _parse_stash_raw(raw_text: str) -> dict[str, str]:
    """Extract ``key=\"value\"`` pairs from an ES notable stash ``_raw`` line."""
    if not raw_text:
        return {}
    return {key: value for key, value in _RAW_KV_RE.findall(raw_text)}


def _enrich_notable_row(row: dict[str, Any]) -> dict[str, Any]:
    """Merge top-level Splunk fields with KV pairs parsed from ``_raw``."""
    merged: dict[str, Any] = dict(row)
    parsed = _parse_stash_raw(str(row.get("_raw") or ""))
    for key, value in parsed.items():
        if merged.get(key) in (None, ""):
            merged[key] = value
    return merged


def _spl_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _stable_external_id(row: dict[str, Any]) -> str:
    """Replay-stable notable identity for checkpoint + ingest dedup.

    Prefer vendor GUIDs. When Splunk omits them (common on ``index=notable``
    stash rows), hash the firing identity so a 90-day re-poll of the same
    notable does not mint a new alert on every Sync.
    """
    for key in ("source_guid", "orig_sid", "event_id", "source_event_id"):
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    cd = row.get("_cd")
    if cd not in (None, ""):
        return str(cd)
    parts = [
        str(row.get("_time") or ""),
        str(row.get("search_name") or row.get("source") or ""),
        str(row.get("host") or row.get("dvc") or row.get("dest") or ""),
        str(row.get("src") or row.get("src_ip") or ""),
        str(row.get("dest_port") or ""),
        str(row.get("orig_rid") or ""),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:32]


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
                    auth=True,
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
                    auth=True,
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
                    default=_DEFAULT_NOTABLE_SPL,
                    help_text=(
                        "Ad-hoc SPL posted to /services/search/jobs. "
                        "Default pulls fired notables from index=notable. "
                        "Use | rest … only for the ES rule catalog (definitions, not incidents)."
                    ),
                ),
                Field(
                    "earliest_time",
                    "string",
                    "Earliest time",
                    required=False,
                    default="-90d@d",
                    help_text="First-poll / backfill window (e.g. -90d@d). Later polls use the 30m cadence.",
                ),
                Field(
                    "poll_interval_seconds",
                    "number",
                    "Poll interval (seconds)",
                    required=False,
                    default=_DEFAULT_POLL_INTERVAL_SECONDS,
                    help_text="How often to pull new notables (default 1800 = 30 minutes). Duplicates are skipped.",
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
        ssl_verify: bool = False,
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
        self._ssl_verify = _coerce_bool(ssl_verify, default=False)
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
                detail = str(exc).replace("\r", " ").replace("\n", " ")[:240]
                logger.warning(
                    "splunk.test_connection.failed",
                    error_type=type(exc).__name__,
                    error=detail,
                )
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__,
                }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # First poll / no checkpoint → backfill window (``earliest_time``).
        # Later polls → cadence window with a small overlap so we don't miss
        # edge events; connector + fusion dedupe by source_guid / fingerprint.
        if self._checkpoint:
            lookback = max(int(since_seconds), 60) + 120
            earliest = f"-{lookback}s"
        elif self._custom_search:
            earliest = self._earliest_time
        else:
            earliest = f"-{max(1, int(since_seconds))}s"
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
            search = _normalize_custom_spl(custom)
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
        return _stable_external_id(row)

    def _order_and_checkpoint(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        enriched = [_enrich_notable_row(r) if isinstance(r, dict) else r for r in rows]
        ordered = sorted(enriched, key=lambda r: (self._event_time(r), self._event_tiebreak(r)))
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

    async def lookup_notable(self, title: str, host: str | None = None) -> dict[str, Any] | None:
        """Return the latest index=notable row for this ES rule + host."""
        title_q = _spl_quote((title or "").strip())
        if not title_q:
            return None
        parts = [
            "search index=notable",
            f'(search_name="{title_q}" OR source="{title_q}")',
        ]
        if host and host.strip():
            host_q = _spl_quote(host.strip())
            parts.append(f'(dvc="{host_q}" OR dest="{host_q}" OR host="{host_q}")')
        spl = " ".join(parts) + " | sort 0 - _time | head 5"
        async with httpx.AsyncClient(**self._client_kwargs()) as client:
            resp = await client.post(
                f"{self._base_url}/services/search/jobs",
                headers=self._headers(),
                data={
                    "search": spl,
                    "earliest_time": self._earliest_time,
                    "latest_time": "now",
                    "output_mode": "json",
                },
            )
            resp.raise_for_status()
            sid = self._extract_sid(resp)
            if not sid:
                return None
            await self._await_job(client, sid)
            rows = await self._collect_results(client, sid)
        if not rows:
            return None
        return self.normalize(rows[0])

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

        row = _enrich_notable_row(raw)
        external_id = _stable_external_id(row)
        title = (
            row.get("search_name")
            or row.get("orig_rule_title")
            or row.get("source")
            or "Splunk Notable Event"
        )
        description = str(
            row.get("orig_rule_description")
            or row.get("description")
            or row.get("_raw")
            or ""
        )
        hostname = row.get("dvc") or row.get("dest") or row.get("host")
        created_at = row.get("_time")
        return {
            "source": self.connector_id,
            "external_id": external_id,
            "event_id": external_id,
            "title": str(title),
            "description": description[:2000],
            "severity": _map_severity(row.get("urgency") or row.get("severity")),
            "src_ip": row.get("src") or row.get("src_ip"),
            "hostname": hostname,
            "raw_event": row,
            "created_at": str(created_at) if created_at is not None else None,
        }
