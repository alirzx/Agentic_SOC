"""
Splunk connector.
Runs saved searches, custom SPL, or fetches notable events from Splunk SIEM.
Supports Bearer token or Basic (username/password) auth.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
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

# Mission Control stash fields extracted from ``index=agentic*`` ``_raw``.
# Time window is applied via ``earliest_time`` / poll cadence — do not embed
# ``earliest=`` in the SPL (it fights the connector's lookback).
#
# Keep this list wide: ESCU / ES notables carry MITRE + analytic-story
# annotations and endpoint/identity context that triage needs. Verified
# against live Splunk ``index=agentic* | extract | fieldsummary``.
_DEFAULT_INDEX = "agentic*"
_MC_TABLE_FIELDS = (
    "_time notable_id search_name detection_id detection_type "
    "dvc dest dest_ip dest_port dest_nt_host dest_os dest_owner dest_priority "
    "dest_category dest_bunit dest_country dest_city dest_mac "
    "src src_ip src_port host user user_name "
    "severity urgency status owner disposition security_domain transport is_prohibited "
    "orig_rule_title orig_rule_description source_event_id source_guid "
    "annotations annotations_mitre_attack annotations_analytic_story "
    "annotations_kill_chain_phases annotations_cis20 annotations_nist "
    "annotations_data_source annotations_type annotations_type_list "
    "action EventID Image Path ProcessID ImageLoaded ScriptBlockText "
    "entity entity_type risk_object risk_score normalized_risk_object "
    "contributing_events_search app authentication_method signature signature_id"
)
_MISSION_CONTROL_PIPELINE = (
    "| extract "
    "| eval notable_id=coalesce(source_event_id, source_guid, detection_id) "
    f"| table {_MC_TABLE_FIELDS} "
    "| sort 0 - _time"
)
_DEFAULT_NOTABLE_SPL = f"search index={_DEFAULT_INDEX} {_MISSION_CONTROL_PIPELINE}"
_MITRE_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Default scheduler cadence for Splunk (30 minutes).
_DEFAULT_POLL_INTERVAL_SECONDS = 1800


def _first_scalar(value: Any) -> Any:
    """Unwrap Splunk multivalue fields (list/tuple) to the first non-empty item."""
    if isinstance(value, (list, tuple)):
        for item in value:
            if item is None:
                continue
            if isinstance(item, str) and not item.strip():
                continue
            return item
        return None
    return value


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


def mission_control_spl(filters: str = "", *, limit: int | None = None) -> str:
    """Fired notables from ``index=agentic*`` as a flat JSON-ready table."""
    extra = f" {filters.strip()}" if filters.strip() else ""
    spl = f"search index={_DEFAULT_INDEX}{extra} {_MISSION_CONTROL_PIPELINE}"
    if limit is not None:
        spl = f"{spl} | head {int(limit)}"
    return spl


def _is_replaceable_notable_search(spl: str) -> bool:
    """True when stored custom SPL should be superseded by the current default.

    Covers empty config, legacy ``index=notable`` stock polls (with or without
    extract), bare ``index=agentic*`` table polls without extract, and older
    Mission Control pipelines that omit MITRE annotation columns — so existing
    connector rows pick up the current wide field table.
    """
    stripped = (spl or "").strip()
    if not stripped:
        return True
    lower = stripped.lower()
    if lower == _DEFAULT_NOTABLE_SPL.lower():
        return False
    if lower.startswith("| rest") or "/services/" in lower:
        return False
    if lower.startswith("search index=notable"):
        return True
    if lower.startswith(f"search index={_DEFAULT_INDEX.lower()}"):
        if "| extract" not in lower:
            return True
        # Prior defaults that already used extract but dropped MITRE / wide fields.
        if "annotations_mitre_attack" not in lower:
            return True
    return False


def _mitre_techniques_from_row(row: dict[str, Any]) -> list[str]:
    """Pull MITRE technique IDs from flattened or nested notable annotations."""
    found: list[str] = []

    def _extend(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, list):
            for item in value:
                _extend(item)
            return
        if isinstance(value, dict):
            for key in ("mitre_attack", "technique_id", "id", "technique"):
                if key in value:
                    _extend(value.get(key))
            return
        text = str(value).strip()
        if not text:
            return
        if text.startswith("{") or text.startswith("["):
            try:
                _extend(json.loads(text))
                return
            except (ValueError, TypeError):
                pass
        for match in _MITRE_TECH_RE.findall(text):
            tid = match.upper()
            if tid not in found:
                found.append(tid)

    for key in (
        "annotations_mitre_attack",
        "annotations.mitre_attack",
        "mitre_attack",
        "mitre",
        "signature",
    ):
        _extend(row.get(key))
    annotations = row.get("annotations")
    if isinstance(annotations, dict):
        _extend(annotations.get("mitre_attack"))
    else:
        _extend(annotations)
    return found


def _should_oneshot(spl: str) -> bool:
    """Whether to use Splunk ``exec_mode=oneshot``.

    Always ``False``: oneshot silently caps result sets (commonly ~100 rows),
    which drops the rest of a notable backfill and then advances the
    checkpoint past the missing events. Use a normal search job + paged
    ``/results`` instead (#529 follow-up).
    """
    _ = spl  # signature kept for call-site clarity / tests
    return False


def _stable_external_id(row: dict[str, Any]) -> str:
    """Replay-stable notable identity for checkpoint + ingest dedup.

    Prefer vendor GUIDs. When Splunk omits them (common on agentic* stash
    rows), hash the firing identity so a 90-day re-poll of the same
    notable does not mint a new alert on every Sync.
    """
    for key in (
        "notable_id",
        "source_guid",
        "source_event_id",
        "detection_id",
        "orig_sid",
        "event_id",
    ):
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
                        "Default tables Mission Control stash fields from "
                        "index=agentic* including annotations_mitre_attack, "
                        "orig_rule_*, dest/src, endpoint/identity context. "
                        "Use | rest … only for the ES rule catalog (definitions, not incidents)."
                    ),
                ),
                Field(
                    "earliest_time",
                    "string",
                    "Earliest time",
                    required=False,
                    default="-90d@d",
                    help_text="First-poll / backfill window (e.g. -90d@d). Later polls resume from the saved checkpoint time.",
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

    def _client_kwargs(self, *, timeout: float = 90.0) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"timeout": timeout, "verify": self._ssl_verify}
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

    def _poll_earliest(self, since_seconds: int) -> str:
        """SPL earliest_time for this poll.

        * No checkpoint → configured ``earliest_time`` (default ``-90d@d``).
        * With checkpoint → resume from the stored event timestamp so a long
          outage or a historical notable dump is not clipped to one poll
          cadence (the old ``-{poll_interval+120}s`` window dropped anything
          older than ~32 minutes once a checkpoint existed).
        * Checkpoint without a parseable time → cadence lookback as fallback.
        """
        if not self._checkpoint:
            return self._earliest_time
        cp_time = str(self._checkpoint.get("time") or "").strip()
        if cp_time:
            return cp_time
        lookback = max(int(since_seconds), 60) + 120
        return f"-{lookback}s"

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # First poll / no checkpoint → connector earliest_time (default 90d).
        # Later polls → from checkpoint time; connector + fusion dedupe by
        # source_guid / fingerprint so already-accepted rows are skipped.
        earliest = self._poll_earliest(since_seconds)
        async with httpx.AsyncClient(**self._client_kwargs()) as client:
            rows = await self._fetch_rows(client, earliest)

        ordered = self._order_and_checkpoint(rows)
        return [self.normalize(r) for r in ordered]

    async def _fetch_rows(self, client: httpx.AsyncClient, earliest: str) -> list[dict[str, Any]]:
        """Run the configured search and return result rows."""
        custom = self._custom_search
        if custom and not _is_replaceable_notable_search(custom):
            search = _normalize_custom_spl(custom)
            return await self._run_adhoc(
                client, search, earliest, oneshot=_should_oneshot(search)
            )
        ss = self._saved_search
        if ss and not ss.startswith("index="):
            sid = await self._dispatch_saved(client, ss, earliest)
            if not sid:
                return []
            await self._await_job(client, sid)
            return await self._collect_results(client, sid)
        if ss.startswith("index=") and ss[len("index=") :].strip() not in ("", "notable", _DEFAULT_INDEX):
            index = ss[len("index=") :].strip()
            return await self._run_adhoc(client, f"search index={index}", earliest, oneshot=False)
        return await self._run_adhoc(client, mission_control_spl(), earliest, oneshot=False)

    async def _dispatch_saved(
        self, client: httpx.AsyncClient, name: str, earliest: str
    ) -> str | None:
        resp = await client.post(
            f"{self._base_url}/services/saved/searches/{quote(name, safe='')}/dispatch",
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

    async def _run_adhoc(
        self,
        client: httpx.AsyncClient,
        search: str,
        earliest: str,
        *,
        oneshot: bool,
    ) -> list[dict[str, Any]]:
        """POST /services/search/jobs. Oneshot returns JSON rows in one round-trip."""
        data: dict[str, str] = {
            "search": search,
            "earliest_time": earliest,
            "latest_time": "now",
            "output_mode": "json",
        }
        if oneshot:
            data["exec_mode"] = "oneshot"
        resp = await client.post(
            f"{self._base_url}/services/search/jobs",
            headers=self._headers(),
            data=data,
        )
        resp.raise_for_status()
        if oneshot:
            try:
                body = resp.json()
            except ValueError:
                body = None
            if isinstance(body, dict) and "results" in body:
                rows = body.get("results") or []
                return [r for r in rows if isinstance(r, dict)]
        sid = self._extract_sid(resp)
        if not sid:
            return []
        await self._await_job(client, sid)
        return await self._collect_results(client, sid)

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

    async def lookup_notable(
        self,
        title: str,
        host: str | None = None,
        notable_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Return the latest index=agentic* row for this ES rule (+ optional entity/id).

        Tries, in order:
        1. ``notable_id`` / ``source_event_id`` / ``source_guid``
        2. ``search_name`` + entity (host/dvc/dest/**src**)
        3. ``search_name`` alone (entity filter often fails for identity rules
           where the only entity is ``src=B_309`` not ``host``)
        """
        async with httpx.AsyncClient(**self._client_kwargs()) as client:
            nid = (notable_id or "").strip()
            if nid:
                nid_q = _spl_quote(nid)
                rows = await self._run_adhoc(
                    client,
                    mission_control_spl(
                        f'(notable_id="{nid_q}" OR source_event_id="{nid_q}" OR source_guid="{nid_q}")',
                        limit=5,
                    ),
                    self._earliest_time,
                    oneshot=False,
                )
                if rows:
                    return self.normalize(rows[0])

            title_q = _spl_quote((title or "").strip())
            if not title_q:
                return None
            title_filter = f'(search_name="{title_q}" OR source="{title_q}")'
            entity = (host or "").strip()
            if entity:
                entity_q = _spl_quote(entity)
                # Include src/src_ip — password-spray style notables often only set src.
                entity_filter = (
                    f'{title_filter} ('
                    f'dvc="{entity_q}" OR dest="{entity_q}" OR host="{entity_q}" '
                    f'OR src="{entity_q}" OR src_ip="{entity_q}")'
                )
                rows = await self._run_adhoc(
                    client,
                    mission_control_spl(entity_filter, limit=5),
                    self._earliest_time,
                    oneshot=False,
                )
                if rows:
                    return self.normalize(rows[0])

            rows = await self._run_adhoc(
                client,
                mission_control_spl(title_filter, limit=5),
                self._earliest_time,
                oneshot=False,
            )
            if not rows:
                return None
            return self.normalize(rows[0])

    async def query(self, unified: UnifiedQuery) -> list[dict[str, Any]]:
        """Run a translated SPL search and return raw rows."""
        index = self._saved_search if self._saved_search.startswith("index=") else _DEFAULT_INDEX
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
        hostname = _first_scalar(
            row.get("dvc") or row.get("dest") or row.get("host") or row.get("asset")
        )
        if hostname is not None:
            hostname = str(hostname)
        src_ip = _first_scalar(row.get("src") or row.get("src_ip"))
        if src_ip is not None:
            src_ip = str(src_ip)
        created_at = row.get("_time")
        if not row.get("notable_id"):
            row["notable_id"] = external_id
        mitre = _mitre_techniques_from_row(row)
        if mitre and not row.get("annotations_mitre_attack"):
            row["annotations_mitre_attack"] = mitre
        return {
            "source": self.connector_id,
            "external_id": external_id,
            "event_id": external_id,
            "title": str(title),
            "description": description[:4000],
            "severity": _map_severity(row.get("urgency") or row.get("severity")),
            "src_ip": src_ip,
            "hostname": hostname,
            "mitre_techniques": mitre,
            "raw_event": row,
            "created_at": str(created_at) if created_at is not None else None,
        }
