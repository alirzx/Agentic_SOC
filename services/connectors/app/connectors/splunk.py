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
import os
from datetime import datetime, timedelta, timezone
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
# Inclusive Splunk earliest_time re-returns the watermark row; keep a rolling
# set of accepted external ids so overlapping polls never re-count as ingested.
_CHECKPOINT_SEEN_CAP = 5_000
# After a long outage, resuming from the raw checkpoint timestamp can ask
# Splunk for days of notables in one job → timeout → unhealthy forever.
# Cap each poll's catch-up window; ``seen`` still dedupes overlap.
_MAX_CATCHUP_SECONDS = int(os.getenv("AISOC_SPLUNK_MAX_CATCHUP_SECONDS", str(6 * 3600)))
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

# Splunk notable index with comprehensive extraction and LLM-ready payload.
# Time window is applied via ``earliest_time`` / poll cadence — do not embed
# ``earliest=`` in the SPL (it fights the connector's lookback).
_DEFAULT_INDEX = "notable"
_MISSION_CONTROL_PIPELINE = r"""
| eval notable_raw=_raw
| eval rule_specific_json=json_object()
| foreach *
    [ eval rule_specific_json=if(
        isnotnull('<<FIELD>>')
        AND NOT match("<<FIELD>>", "^(_.*|date_.*|info_.*|orig_.*|annotations.*|risk_.*|all_risk_objects|tag.*|source.*|host|index|time|count|punct|linecount|splunk_server|timeendpos|timestartpos|eventtype|search_name|rule_.*|notable_.*|event_id|event_hash|drilldown_.*|contributing_events_search|entity|entity_type|normalized_risk_object|severity|urgency|status|status_label|owner|disposition|detection_type|security_domain|threat_object|threat_object_type|rule_specific_json)$"),
        json_set_exact(rule_specific_json, "<<FIELD>>", '<<FIELD>>'),
        rule_specific_json) ]
| eval search_name=coalesce(search_name, source)
| eval notable_id=coalesce(source_guid, source_event_id, event_id, if(isnotnull(orig_sid) AND isnotnull(orig_rid), orig_sid . "@@" . orig_rid, null()))
| join type=left search_name
    [ | rest splunk_server=local count=0 /servicesNS/-/-/saved/searches
    | search action.correlationsearch.enabled=1
    | rename title as search_name, search as rule_spl, description as rule_description_rest,
             "action.notable.param.rule_title" as title_template_rest,
             "action.notable.param.rule_description" as description_template_rest,
             "dispatch.earliest_time" as rule_earliest,
             "dispatch.latest_time" as rule_latest
    | dedup search_name
    | fields search_name rule_spl rule_description_rest title_template_rest description_template_rest rule_earliest rule_latest ]
| eval title_template_raw=coalesce(title_template_rest, orig_rule_title, rule_title)
| eval description_template_raw=coalesce(description_template_rest, orig_rule_description, rule_description, rule_description_rest)
| eval rule_title=title_template_raw
| eval rule_description=description_template_raw
| expandtoken rule_title, rule_description
| eval annotations=mvdedup(annotations)
| fields - _raw _bkt _cd _indextime _kv _serial _si _meta date_* punct
| mvexpand annotations
| rename annotations as _blob
| eval _j_attack_raw = json_extract(_blob, "mitre_attack"),
       _j_story_raw = json_extract(_blob, "analytic_story"),
       _j_cve_raw = json_extract(_blob, "cve"),
       _j_cis20_raw = json_extract(_blob, "cis20"),
       _j_ds_raw = json_extract(_blob, "data_source"),
       _j_kc_raw = json_extract(_blob, "kill_chain_phases"),
       _j_nist_raw = json_extract(_blob, "nist"),
       _j_type_raw = json_extract(_blob, "type"),
       _j_tlist_raw = json_extract(_blob, "type_list")
| eval _j_attack = if(match(_j_attack_raw, "^\["), json_array_to_mv(_j_attack_raw), _j_attack_raw),
       _j_story = if(match(_j_story_raw, "^\["), json_array_to_mv(_j_story_raw), _j_story_raw),
       _j_cve = if(match(_j_cve_raw, "^\["), json_array_to_mv(_j_cve_raw), _j_cve_raw),
       _j_cis20 = if(match(_j_cis20_raw, "^\["), json_array_to_mv(_j_cis20_raw), _j_cis20_raw),
       _j_ds = if(match(_j_ds_raw, "^\["), json_array_to_mv(_j_ds_raw), _j_ds_raw),
       _j_kc = if(match(_j_kc_raw, "^\["), json_array_to_mv(_j_kc_raw), _j_kc_raw),
       _j_nist = if(match(_j_nist_raw, "^\["), json_array_to_mv(_j_nist_raw), _j_nist_raw),
       _j_type = _j_type_raw,
       _j_tlist = if(match(_j_tlist_raw, "^\["), json_array_to_mv(_j_tlist_raw), _j_tlist_raw)
| fields - _j_*_raw
| stats values(_j_attack) as _j_attack values(_j_story) as _j_story values(_j_cve) as _j_cve
        values(_j_cis20) as _j_cis20 values(_j_ds) as _j_ds values(_j_kc) as _j_kc
        values(_j_nist) as _j_nist values(_j_type) as _j_type values(_j_tlist) as _j_tlist
        first(search_name) as search_name first(severity) as severity first(risk_score) as risk_score
        first(risk_object) as risk_object first(risk_object_type) as risk_object_type
        first(detection_type) as detection_type first(security_domain) as security_domain
        first(orig_security_domain) as orig_security_domain
        first(rule_title) as rule_title
        first(title_template_raw) as title_template_raw
        first(rule_description) as rule_description
        first(description_template_raw) as description_template_raw
        first(rule_spl) as rule_spl first(info_min_time) as info_min_time
        first(info_max_time) as info_max_time first(info_search_time) as info_search_time
        first(rule_earliest) as rule_earliest first(rule_latest) as rule_latest
        first(contributing_events_search) as contributing_events_search first(notable_raw) as notable_raw
        first(rule_specific_json) as rule_specific_json first(_time) as _time first(status) as status
        first(owner) as owner first(urgency) as urgency first(disposition) as disposition
        first(status_label) as status_label first(rule_id) as rule_id first(count) as finding_count
        first(risk_message) as risk_message first(entity) as entity first(entity_type) as entity_type
        first(next_steps) as next_steps first(investigation_type) as investigation_type
        first(source_guid) as source_guid first(source_event_id) as source_event_id
        first(detection_id) as detection_id first(orig_sid) as orig_sid first(orig_rid) as orig_rid
        first(event_id) as event_id first(host) as host
        by notable_id
| eval annotation_mitre_attack = mvdedup(_j_attack), annotation_analytic_story = mvdedup(_j_story),
       annotation_cve = mvdedup(_j_cve), annotation_cis20 = mvdedup(_j_cis20),
       annotation_data_source = mvdedup(_j_ds), annotation_kill_chain_phases = mvdedup(_j_kc),
       annotation_nist = mvdedup(_j_nist), annotation_type = mvdedup(_j_type),
       annotation_type_list = mvdedup(_j_tlist)
| fields - _j_*
| eval annotations_obj = json_object(
       "mitre_attack", annotation_mitre_attack, "analytic_story", annotation_analytic_story,
       "cve", annotation_cve, "cis20", annotation_cis20, "data_source", annotation_data_source,
       "kill_chain_phases", annotation_kill_chain_phases, "nist", annotation_nist,
       "type", annotation_type, "type_list", annotation_type_list)
| eval _phase="main"
| appendpipe
    [ | where isnotnull(rule_spl) AND rule_spl!=""
    | eval _phase="macros"
    | rex field=rule_spl max_match=0 "`(?<macro_ref>[a-zA-Z0-9_]+)(?:`|\()"
    | eval macro_ref=mvdedup(macro_ref)
    | eval macro_ref=mvfilter(NOT match(macro_ref, "^(security_content_summariesonly|security_content_ctime|drop_dm_object_name|get_correlations|get_risk_severity|summariesonly|notable|risk_notable|get_event_id|get_rule_id|detectable_name|uptime2string|convert_to_epoch|isnum)$"))
    | mvexpand macro_ref
    | where isnotnull(macro_ref) AND macro_ref!=""
    | join type=left macro_ref
        [ | rest splunk_server=local count=0 /servicesNS/-/-/configs/conf-macros
        | rename title as macro_ref, definition as macro_definition, description as macro_description
        | fields macro_ref macro_definition macro_description ]
    | eval macro_definition=coalesce(macro_definition, "(not found)")
    | eval macro_category=case(
        match(macro_ref, "_filter$"), "filter",
        match(macro_ref, "^(sysmon|win_eventlog|linux_.*|macos_.*|.*_index)$"), "data_source",
        match(macro_ref, "^process_.*$"), "process_match",
        match(macro_definition, "^[0-9.]+$"), "config",
        true(), "other")
    | eval macro_is_active_filter=if(macro_category="filter" AND macro_definition!="search *" AND macro_definition!="(not found)" AND macro_definition!="", "yes", "no")
    | eval macro_entry=json_object("name", macro_ref, "category", macro_category, "is_active_filter", macro_is_active_filter, "definition", macro_definition, "description", macro_description)
    | stats values(macro_entry) as macro_entries_mv by notable_id
    | eval macro_definitions="[" . mvjoin(macro_entries_mv, ",") . "]"
    | fields notable_id macro_definitions _phase ]
| eventstats max(macro_definitions) as macro_definitions by notable_id
| where _phase="main"
| fields - _phase
| eval macro_definitions=coalesce(macro_definitions, "[]")
| eval event_epoch=strptime(json_extract(rule_specific_json, "firstTime"), "%Y-%m-%dT%H:%M:%S")
| eval event_time_source=if(isnotnull(event_epoch), "first_event", "alert_time_fallback")
| eval event_epoch=coalesce(event_epoch, _time)
| eval _wday=strftime(event_epoch, "%A"), _hour=tonumber(strftime(event_epoch, "%H"))
| eval is_business_hours=case(
    event_time_source!="first_event", "unknown",
    _hour>=8 AND _hour<18 AND match(_wday, "^(Saturday|Sunday|Monday|Tuesday|Wednesday)$"), "yes",
    true(), "no")
| fields - _wday _hour
| eval _ist=tonumber(info_search_time)
| eval _imin=tonumber(info_min_time), _imax=tonumber(info_max_time)
| eval window_source=case(
    _imin>0 AND _imax>0, "notable_info",
    isnotnull(rule_earliest) AND isnotnull(_ist), "saved_search_dispatch",
    true(), "unknown")
| eval window_earliest=case(
    _imin>0, _imin,
    window_source="saved_search_dispatch", relative_time(_ist, rule_earliest),
    true(), null())
| eval window_latest=case(
    _imax>0, _imax,
    window_source="saved_search_dispatch" AND isnotnull(rule_latest), relative_time(_ist, rule_latest),
    true(), null())
| eval llm_payload=json_object(
    "alert_id", notable_id,
    "alert_time", strftime(_time, "%Y-%m-%dT%H:%M:%S%z"),
    "event_time", strftime(event_epoch, "%Y-%m-%dT%H:%M:%S%z"),
    "event_time_source", event_time_source,
    "date_context", json_object("wday", strftime(event_epoch, "%A"), "hour", tonumber(strftime(event_epoch, "%H")), "is_business_hours", is_business_hours),
    "rule_name", search_name,
    "severity", severity,
    "finding_count", finding_count,
    "risk_score", risk_score,
    "risk_object", risk_object,
    "risk_object_type", risk_object_type,
    "entity", entity,
    "entity_type", entity_type,
    "detection_type", detection_type,
    "security_domain", coalesce(orig_security_domain, security_domain),
    "investigation_type", investigation_type,
    "time_window", json_object(
        "earliest", strftime(window_earliest, "%Y-%m-%dT%H:%M:%S%z"),
        "latest", strftime(window_latest, "%Y-%m-%dT%H:%M:%S%z"),
        "search_time", strftime(_ist, "%Y-%m-%dT%H:%M:%S%z"),
        "source", window_source),
    "annotations", json(annotations_obj),
    "rule", json_object(
        "title", rule_title,
        "title_template", title_template_raw,
        "description", rule_description,
        "description_template", description_template_raw,
        "risk_message", risk_message,
        "next_steps", next_steps,
        "spl", rule_spl,
        "spl_caveat", "Current saved-search definition; macros *_filter not expanded.",
        "macro_definitions", json(macro_definitions),
        "macro_definitions_caveat", "Current definitions from conf-macros. category=filter with is_active_filter=yes means an allowlist is active. category=data_source shows detection scope. category=process_match shows exact process matching. category=config shows threshold values."),
    "investigation_hint", contributing_events_search,
    "alert_fields", json(rule_specific_json))
| eval analyst_labels=json_object("status", status, "status_label", status_label, "owner", owner, "urgency", urgency, "disposition", disposition)
| eval orig_rule_title=coalesce(title_template_raw, search_name),
       orig_rule_description=coalesce(description_template_raw, rule_description),
       annotations=json(annotations_obj),
       annotations_mitre_attack=mvdedup(annotation_mitre_attack),
       annotations_analytic_story=mvdedup(annotation_analytic_story),
       annotations_kill_chain_phases=mvdedup(annotation_kill_chain_phases),
       annotations_cve=mvdedup(annotation_cve),
       annotations_data_source=mvdedup(annotation_data_source),
       annotations_cis20=mvdedup(annotation_cis20),
       annotations_nist=mvdedup(annotation_nist),
       annotations_type=mvdedup(annotation_type),
       annotations_type_list=mvdedup(annotation_type_list)
| table _time event_epoch event_time_source notable_id source_guid source_event_id detection_id
        orig_sid orig_rid event_id rule_id search_name orig_rule_title orig_rule_description
        severity urgency status owner disposition detection_type security_domain entity entity_type
        risk_object risk_object_type risk_score annotations annotations_mitre_attack
        annotations_analytic_story annotations_kill_chain_phases annotations_cve annotations_data_source
        annotations_cis20 annotations_nist annotations_type annotations_type_list
        llm_payload analyst_labels notable_raw
| sort 0 - _time
"""

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
    """Fired notables from ``index=notable`` as an LLM-ready enriched payload."""
    extra = f" {filters.strip()}" if filters.strip() else ""
    spl = f"search index={_DEFAULT_INDEX}{extra} {_MISSION_CONTROL_PIPELINE}"
    if limit is not None:
        # Insert head before the final sort to avoid processing the entire result set
        spl = spl.replace("| sort 0 - _time", f"| head {int(limit)} | sort 0 - _time")
    return spl


def _is_replaceable_notable_search(spl: str) -> bool:
    """True only when *no* operator SPL is configured (empty / whitespace).

    Non-empty ``custom_search`` is always honored; only a blank field falls
    through to saved-search / platform default (index=notable with full
    enrichment pipeline).
    """
    return not (spl or "").strip()


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
        "Notable Name",
        "notable_name",
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


def _time_sort_key(raw: str | None) -> float | None:
    """Normalize Splunk ``_time`` for watermark compares (ISO / epoch / Z vs offset)."""
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    normalized = text.replace("Z", "+00:00") if text.endswith("Z") else text
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


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
                        "Ad-hoc SPL posted to /services/search/jobs on every poll. "
                        "Whatever you save here is what runs — no silent rewrite. "
                        "Leave blank to use a Saved Search Name or the platform default "
                        "(index=notable with comprehensive enrichment, macro expansion, "
                        "and LLM-ready payload generation). "
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
        self._checkpoint: dict[str, Any] | None = None
        self._next_checkpoint: dict[str, Any] | None = None

    def set_checkpoint(self, checkpoint: dict[str, Any] | None) -> None:
        """Seed the poll with the last-accepted checkpoint (scheduler-owned)."""
        if not isinstance(checkpoint, dict):
            self._checkpoint = None
            return
        seen_raw = checkpoint.get("seen")
        seen: list[str] = []
        if isinstance(seen_raw, list):
            seen = [str(item) for item in seen_raw if item not in (None, "")][-_CHECKPOINT_SEEN_CAP:]
        if checkpoint.get("time") or checkpoint.get("id") or seen:
            self._checkpoint = {
                "time": str(checkpoint.get("time") or ""),
                "id": str(checkpoint.get("id") or ""),
                "seen": seen,
            }
        else:
            self._checkpoint = None

    def get_checkpoint(self) -> dict[str, Any] | None:
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
        * With checkpoint → resume from the stored event timestamp, but never
          open a window larger than ``_MAX_CATCHUP_SECONDS`` in one poll
          (avoids Splunk job timeouts that leave the connector unhealthy).
        * Checkpoint without a parseable time → cadence lookback as fallback.
        """
        if not self._checkpoint:
            return self._earliest_time
        cp_time = str(self._checkpoint.get("time") or "").strip()
        if not cp_time:
            lookback = max(int(since_seconds), 60) + 120
            return f"-{lookback}s"
        cp_ts = _time_sort_key(cp_time)
        floor = datetime.now(timezone.utc) - timedelta(seconds=max(300, _MAX_CATCHUP_SECONDS))
        if cp_ts is not None and cp_ts < floor.timestamp():
            return floor.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
        return cp_time

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
        """Run the configured search and return result rows.

        Precedence: non-empty ``custom_search`` (operator UI) → named saved
        search → platform Mission Control default. Never rewrite a
        non-empty custom SPL.
        """
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
        try:
            resp.raise_for_status()
        except Exception as e:
            logger.error(
                "splunk.query_failed",
                status=resp.status_code,
                query=search,
                error=str(e),
                response_text=resp.text[:500],
            )
            raise
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
        # Surface timeout to the scheduler so the poll is recorded as a failure
        # instead of shipping a silent empty/partial result and looking "synced".
        raise TimeoutError(f"splunk search job {sid} did not finish within poll budget")

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
        """Return only events newer than the watermark / not already seen.

        Splunk ``earliest_time`` is inclusive, so every poll re-reads the
        watermark second. Without an id set, those overlaps were pushed again
        and ``events_ingested`` grew even when nothing new arrived. Timeless
        catalog rows (no ``_time``) use the same ``seen`` ring so Sync does
        not re-count the full snapshot.
        """
        enriched = [_enrich_notable_row(r) if isinstance(r, dict) else r for r in rows]
        ordered = sorted(
            enriched,
            key=lambda r: (
                _time_sort_key(self._event_time(r)) is None,
                _time_sort_key(self._event_time(r)) or 0.0,
                self._event_tiebreak(r),
            ),
        )
        cp = self._checkpoint or {}
        seen: set[str] = {str(item) for item in (cp.get("seen") or []) if item}
        cp_time_key = _time_sort_key(str(cp.get("time") or ""))
        cp_id = str(cp.get("id") or "")
        has_timed_rows = any(self._event_time(r) for r in ordered)
        fresh: list[dict[str, Any]] = []
        for row in ordered:
            eid = self._event_tiebreak(row)
            if eid and eid in seen:
                continue
            row_time_raw = self._event_time(row)
            row_time_key = _time_sort_key(row_time_raw)
            if has_timed_rows and str(cp.get("time") or "") and row_time_raw:
                if cp_time_key is not None and row_time_key is not None:
                    if (row_time_key, eid) <= (cp_time_key, cp_id):
                        continue
                elif (row_time_raw, eid) <= (str(cp.get("time") or ""), cp_id):
                    # Unparseable timestamps (legacy fixtures) — string compare.
                    continue
            fresh.append(row)
        if not fresh:
            self._next_checkpoint = None
            return []
        merged_seen: list[str] = []
        for item in list(cp.get("seen") or []) + [self._event_tiebreak(r) for r in fresh]:
            text = str(item or "")
            if not text or text in merged_seen:
                continue
            merged_seen.append(text)
        merged_seen = merged_seen[-_CHECKPOINT_SEEN_CAP:]
        last = fresh[-1]
        last_time = self._event_time(last) if has_timed_rows else str(cp.get("time") or "")
        self._next_checkpoint = {
            "time": last_time,
            "id": self._event_tiebreak(last),
            "seen": merged_seen,
        }
        return fresh

    async def lookup_notable(
        self,
        title: str,
        host: str | None = None,
        notable_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Return the latest index=agentic* row for this ES rule (+ optional entity/id).

        Optimized for re-enrich / hydrate: at most **two** oneshot searches
        over a 30-day window (not a full job + 90-day poll).
        """
        # Lookups are small (head 5) — oneshot is fine and much faster than
        # create-job + poll, which was hanging the bulk re-enrich loop.
        lookup_earliest = "-30d"
        async with httpx.AsyncClient(**self._client_kwargs(timeout=60.0)) as client:
            nid = (notable_id or "").strip()
            if nid:
                nid_q = _spl_quote(nid)
                rows = await self._run_adhoc(
                    client,
                    mission_control_spl(
                        f'(notable_id="{nid_q}" OR source_event_id="{nid_q}" OR source_guid="{nid_q}")',
                        limit=3,
                    ),
                    lookup_earliest,
                    oneshot=True,
                )
                if rows:
                    return self.normalize(rows[0])

            title_q = _spl_quote((title or "").strip())
            if not title_q:
                return None
            # Single title search; prefer entity match in Python (avoids a 2nd Splunk trip).
            rows = await self._run_adhoc(
                client,
                mission_control_spl(f'(search_name="{title_q}" OR source="{title_q}")', limit=10),
                lookup_earliest,
                oneshot=True,
            )
            if not rows:
                return None
            entity = (host or "").strip().lower()
            if entity:
                for row in rows:
                    enriched = _enrich_notable_row(row) if isinstance(row, dict) else row
                    hay = " ".join(
                        str(enriched.get(k) or "").lower()
                        for k in ("dvc", "dest", "host", "src", "src_ip")
                    )
                    if entity in hay:
                        return self.normalize(enriched)
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
        # Splunk multivalue fields (e.g. duplicated search_name) must be
        # unwrapped — otherwise title becomes a JSON/list string in Postgres
        # and the Cases/Alerts UI shows ``['Rule', 'Rule']``.
        title = _first_scalar(
            row.get("search_name")
            or row.get("orig_rule_title")
            or row.get("source")
            or "Splunk Notable Event"
        )
        description = str(
            _first_scalar(
                row.get("orig_rule_description")
                or row.get("description")
                or row.get("_raw")
                or ""
            )
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
            "title": str(title) if title is not None else "Splunk Notable Event",
            "description": description[:4000],
            # Severity precedence follows the query: ``severity`` first, ``urgency``
            # only as the ES fallback (the query exposes both).
            "severity": _map_severity(row.get("severity") or row.get("urgency")),
            "src_ip": src_ip,
            "hostname": hostname,
            "mitre_techniques": mitre,
            "raw_event": row,
            "created_at": str(created_at) if created_at is not None else None,
        }
