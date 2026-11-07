"""Splunk enrichment service — builds ``llm_payload`` for alerts.

When a Splunk notable arrives via the simple-query path (or any custom SPL
that does not already produce ``llm_payload``), the connector stores the raw
alert fields but omits the rich LLM evidence envelope.  This service fills
that gap on demand.

Two-stage enrichment
--------------------
1. **REST lookup** — calls Splunk's ``/saved/searches/{search_name}`` and
   ``/configs/conf-macros`` endpoints to fetch the rule definition (SPL,
   description, macros).  Falls through silently if the Splunk instance is
   unreachable or the search name is unknown.

2. **Python payload builder** — assembles the ``llm_payload`` dict from the
   alert's stored fields plus whatever stage-1 returned.  Mirrors the shape
   ``_MISSION_CONTROL_PIPELINE`` produces, so agents and the workbench handle
   one schema regardless of the query mode.

The result is written back to ``alerts.llm_payload`` and a
``runbook_events`` row of ``kind='llm_payload'`` records what happened.

Security
--------
* No ``eval()`` / ``compile()``.
* Log injection: all external strings are sanitised inline (the standard
  ``str(v).replace("\\r","").replace("\\n"," ")[:N]`` pattern).
* Splunk credentials are read from the connector row's ``auth_config``
  (vault-encrypted at rest, decrypted by ``CredentialVault.decrypt_dict``).
  They are never logged or stored in the ledger.
* TLS: the connector's own ``ssl_verify`` flag is honoured; never silently
  disabled.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.connector import Connector
from app.security.credential_vault import CredentialVault
from app.services.runbook.recorder import record_event

logger = logging.getLogger(__name__)

_MAX_MACRO = 40     # maximum macros to fetch per rule
_MACRO_SKIP = frozenset({
    "security_content_summariesonly", "security_content_ctime",
    "drop_dm_object_name", "get_correlations", "get_risk_severity",
    "summariesonly", "notable", "risk_notable", "get_event_id",
    "get_rule_id", "detectable_name", "uptime2string",
    "convert_to_epoch", "isnum",
})
_MACRO_RE = re.compile(r"`([a-zA-Z0-9_]+)(?:`|\()")

# Same exclusion list as the connector's _ALERT_FIELD_EXCLUDE_RE.
_ALERT_FIELD_SKIP_RE = re.compile(
    r"^(_.*|date_.*|info_.*|orig_.*|annotations.*|risk_.*|all_risk_objects|tag.*|source.*|host"
    r"|index|time|splunk_server|timeendpos|timestartpos|eventtype|search_name|rule_.*|notable_.*"
    r"|event_id|event_hash|contributing_events_search|entity|entity_type|normalized_risk_object"
    r"|severity|urgency|status|status_label|owner|disposition|detection_type|security_domain"
    r"|threat_object|threat_object_type|rule_specific_json|llm_payload|runbook_provenance)$"
)


def _safe(v: Any, max_len: int = 200) -> str:
    return str(v).replace("\r", "").replace("\n", " ")[:max_len]


# ── Splunk REST helpers ───────────────────────────────────────────────────────


def _splunk_auth_headers(auth_config: dict[str, Any]) -> dict[str, str]:
    token = str(auth_config.get("token") or "").strip()
    if token:
        return {"Authorization": f"Splunk {token}"}
    username = str(auth_config.get("username") or "").strip()
    password = str(auth_config.get("password") or "")
    import base64
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


async def _splunk_get(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """GET one Splunk REST endpoint.  Returns the parsed JSON or None."""
    url = f"{base_url.rstrip('/')}{path}"
    try:
        resp = await client.get(url, params={"output_mode": "json", **(params or {})})
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "splunk_enrichment.rest_failed url=%s error=%s",
            _safe(url, 120),
            _safe(exc),
        )
        return None


async def fetch_rule_details(
    base_url: str,
    auth_headers: dict[str, str],
    search_name: str,
    ssl_verify: bool,
) -> dict[str, Any]:
    """Fetch saved-search definition + macro definitions for one rule.

    Returns a dict with ``spl``, ``description``, ``macros`` (list), and
    ``caveats`` (list of strings describing what could not be fetched).
    """
    caveats: list[str] = []
    spl: str | None = None
    description: str | None = None
    macros: list[dict[str, Any]] = []

    async with httpx.AsyncClient(verify=ssl_verify, timeout=15.0, headers=auth_headers) as client:
        data = await _splunk_get(client, base_url, f"/servicesNS/-/-/saved/searches/{httpx.URL(path=search_name).path}")
        if data:
            entry = (data.get("entry") or [{}])[0]
            content = entry.get("content") or {}
            spl = content.get("qualifiedSearch") or content.get("search")
            description = content.get("description")
        else:
            caveats.append("saved_search_not_found")

        if spl:
            refs = sorted(
                set(_MACRO_RE.findall(spl)) - _MACRO_SKIP,
            )[:_MAX_MACRO]
            for ref in refs:
                mdata = await _splunk_get(
                    client, base_url,
                    f"/servicesNS/-/-/configs/conf-macros/{httpx.URL(path=ref).path}",
                )
                if not mdata:
                    continue
                mc = ((mdata.get("entry") or [{}])[0]).get("content") or {}
                defn = mc.get("definition") or mc.get("body")
                mcat = (
                    "filter" if ref.endswith("_filter") else
                    "data_source" if re.match(r"^(sysmon|win_eventlog|linux_|macos_|.*_index)", ref) else
                    "process_match" if ref.startswith("process_") else
                    "config" if str(defn or "").strip().lstrip("-").replace(".", "").isdigit() else
                    "other"
                )
                is_active = (
                    "yes" if mcat == "filter" and defn and defn not in ("search *", "(not found)", "")
                    else "no"
                )
                macros.append({
                    "name": ref,
                    "category": mcat,
                    "is_active_filter": is_active,
                    "definition": defn or "(not found)",
                    "description": mc.get("description"),
                })
        else:
            caveats.append("rule_spl_unavailable")

    return {"spl": spl, "description": description, "macros": macros, "caveats": caveats}


# ── Payload builder ───────────────────────────────────────────────────────────


def _first(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        for item in value:
            if item is not None and item != "":
                return item
        return None
    return value


def _iso(epoch: float | int | None) -> str | None:
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(float(epoch), tz=UTC).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def _date_context(epoch: float | None) -> dict[str, Any]:
    if epoch is None:
        return {"wday": None, "hour": None, "is_business_hours": "unknown"}
    try:
        dt = datetime.fromtimestamp(float(epoch), tz=UTC)
        hour = dt.hour
        wday = dt.strftime("%A")
        biz = (
            "yes" if 8 <= hour < 18 and wday in {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
            else "no"
        )
        return {"wday": wday, "hour": hour, "is_business_hours": biz}
    except (TypeError, ValueError, OSError):
        return {"wday": None, "hour": None, "is_business_hours": "unknown"}


def _annotations_from_raw(alert: Alert) -> dict[str, Any]:
    raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    ann: dict[str, Any] = {}
    for key, field_name in {
        "mitre_attack": "annotations_mitre_attack",
        "analytic_story": "annotations_analytic_story",
        "kill_chain_phases": "annotations_kill_chain_phases",
        "cve": "annotations_cve",
        "cis20": "annotations_cis20",
        "nist": "annotations_nist",
        "data_source": "annotations_data_source",
        "type": "annotations_type",
        "type_list": "annotations_type_list",
    }.items():
        val = raw.get(field_name) or raw.get(key)
        ann[key] = val
    # Also check alert's own mitre fields
    if not ann.get("mitre_attack"):
        ann["mitre_attack"] = alert.mitre_techniques or None
    if not ann.get("analytic_story"):
        ann["analytic_story"] = None
    return ann


def build_llm_payload(alert: Alert, rule_details: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a complete ``llm_payload`` from an alert row.

    ``rule_details`` comes from :func:`fetch_rule_details`.  When None or
    when fields are missing, the builder leaves them ``None`` and records
    the gap in ``_meta.caveats``.  It never invents a value.
    """
    caveats: list[str] = ["built_from_alert_fields"]
    rd = rule_details or {}

    raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}

    # Timestamps
    alert_epoch: float | None = alert.created_at.timestamp() if alert.created_at else None
    event_epoch: float | None = alert.event_time.timestamp() if alert.event_time else None
    event_source = "first_event" if alert.event_time else "alert_time_fallback"

    # Alert fields (non-metadata)
    alert_fields = {
        k: v for k, v in raw.items()
        if v not in (None, "") and not _ALERT_FIELD_SKIP_RE.match(str(k))
    }

    annotations = _annotations_from_raw(alert)

    # Time window from raw fields
    info_min = raw.get("info_min_time")
    info_max = raw.get("info_max_time")
    info_search = raw.get("info_search_time")
    window: dict[str, Any] = {"earliest": None, "latest": None, "search_time": None, "source": "unknown"}
    try:
        if info_min and float(info_min) > 0:
            window["earliest"] = _iso(float(info_min))
            window["latest"] = _iso(float(info_max)) if info_max else None
            window["search_time"] = _iso(float(info_search)) if info_search else None
            window["source"] = "notable_info"
    except (TypeError, ValueError):
        pass
    if not window["earliest"]:
        caveats.append("time_window_unavailable")

    if rd.get("caveats"):
        caveats.extend(rd["caveats"])
    if not rd.get("spl"):
        caveats.append("rule_spl_unavailable")

    search_name = (
        alert.rule_name
        or _first(raw.get("search_name") or raw.get("source"))
        or alert.title
    )
    description = rd.get("description") or _first(raw.get("orig_rule_description"))
    contributing = _first(raw.get("contributing_events_search"))
    risk_score = (
        alert.priority
        or _first(raw.get("risk_score"))
    )

    return {
        "alert_id": str(alert.id),
        "alert_time": _iso(alert_epoch),
        "event_time": _iso(event_epoch),
        "event_time_source": event_source,
        "date_context": _date_context(event_epoch),
        "rule_name": search_name,
        "severity": alert.severity,
        "finding_count": _first(raw.get("count") or raw.get("finding_count")),
        "risk_score": risk_score,
        "risk_object": _first(raw.get("risk_object") or raw.get("entity")),
        "risk_object_type": _first(raw.get("risk_object_type") or raw.get("entity_type")),
        "entity": _first(raw.get("entity") or raw.get("dvc") or raw.get("dest") or (alert.affected_hosts or [None])[0]),
        "entity_type": _first(raw.get("entity_type")),
        "detection_type": _first(raw.get("detection_type")),
        "security_domain": _first(raw.get("orig_security_domain") or raw.get("security_domain")),
        "investigation_type": _first(raw.get("investigation_type")),
        "time_window": window,
        "annotations": annotations,
        "rule": {
            "title": search_name,
            "title_template": _first(raw.get("orig_rule_title")),
            "description": description,
            "risk_message": _first(raw.get("risk_message")),
            "next_steps": _first(raw.get("next_steps")),
            "spl": rd.get("spl"),
            "spl_caveat": (
                "Saved-search definition fetched via REST; *_filter macros not applied."
                if rd.get("spl") else
                "Not available — rule definition could not be fetched from Splunk."
            ),
            "macro_definitions": rd.get("macros") or [],
            "macro_definitions_caveat": (
                "Definitions from conf-macros. category=filter with is_active_filter=yes means "
                "an allowlist is active."
            ),
        },
        "investigation_hint": contributing,
        "alert_fields": alert_fields,
        "_meta": {
            "provider": "splunk",
            "mode": "enriched_from_api",
            "caveats": caveats,
            "enriched_at": datetime.now(UTC).isoformat(),
        },
    }


# ── Connector credential lookup ───────────────────────────────────────────────


async def _get_splunk_connector(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    connector_id: uuid.UUID | None,
) -> tuple[Connector | None, dict[str, Any]]:
    """Return the connector row + decrypted auth_config."""
    query = select(Connector).where(
        Connector.tenant_id == tenant_id,
        Connector.connector_type == "splunk",
        Connector.enabled == True,  # noqa: E712
    )
    if connector_id:
        query = query.where(Connector.id == connector_id)
    query = query.limit(1)

    row = (await db.execute(query)).scalar_one_or_none()
    if row is None:
        return None, {}

    try:
        vault = CredentialVault()
        decrypted = vault.decrypt_dict(row.auth_config)
    except Exception:  # noqa: BLE001
        decrypted = row.auth_config

    return row, decrypted


# ── Public entry point ────────────────────────────────────────────────────────


async def enrich_alert_llm_payload(
    db: AsyncSession,
    *,
    alert_id: uuid.UUID,
    tenant_id: uuid.UUID,
    connector_id: uuid.UUID | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Enrich one alert with a full ``llm_payload``.

    Returns a result dict describing what happened:
        ``status``       — "ok" | "skipped" | "error"
        ``source``       — "splunk_rest" | "alert_fields" | "already_present"
        ``llm_payload``  — the built payload dict, or None if skipped
        ``caveats``      — list of advisory strings
    """
    alert_row = (
        await db.execute(
            select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
        )
    ).scalar_one_or_none()
    if alert_row is None:
        return {"status": "error", "source": None, "llm_payload": None, "caveats": ["alert_not_found"]}

    if alert_row.llm_payload and not force:
        return {
            "status": "skipped",
            "source": "already_present",
            "llm_payload": alert_row.llm_payload,
            "caveats": [],
        }

    rule_details: dict[str, Any] | None = None
    source = "alert_fields"

    if alert_row.connector_type == "splunk":
        connector, auth_config = await _get_splunk_connector(db, tenant_id, connector_id)
        if connector:
            base_url = str(auth_config.get("url") or connector.connector_config.get("url") or "").rstrip("/")
            ssl_verify = bool(connector.connector_config.get("ssl_verify", False))
            auth_headers = _splunk_auth_headers(auth_config)
            search_name = (
                alert_row.rule_name
                or str((alert_row.raw_event or {}).get("search_name") or "")
            ).strip()
            if base_url and search_name:
                try:
                    rule_details = await fetch_rule_details(base_url, auth_headers, search_name, ssl_verify)
                    if rule_details.get("spl"):
                        source = "splunk_rest"
                except Exception:  # noqa: BLE001
                    logger.warning(
                        "splunk_enrichment.rest_failed alert=%s",
                        _safe(str(alert_id)),
                        exc_info=True,
                    )

    payload = build_llm_payload(alert_row, rule_details)

    # Persist to the alert row.
    try:
        await db.execute(
            update(Alert)
            .where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
            .values(llm_payload=payload, updated_at=datetime.now(UTC))
        )
        await db.commit()
    except Exception:  # noqa: BLE001
        await db.rollback()
        logger.error("splunk_enrichment.db_write_failed alert=%s", _safe(str(alert_id)), exc_info=True)
        return {"status": "error", "source": source, "llm_payload": payload, "caveats": ["db_write_failed"]}

    # Record in the Runbook ledger.
    caveats = payload.get("_meta", {}).get("caveats", [])
    summary = (
        f"LLM payload built from {'Splunk REST API' if source == 'splunk_rest' else 'alert fields'}."
        + (f" Caveats: {', '.join(caveats[:3])}" if caveats else "")
    )
    try:
        await record_event(
            db,
            tenant_id=tenant_id,
            subject_type="alert",
            subject_id=alert_id,
            stage="enrich",
            kind="llm_payload",
            actor_type="system",
            actor_label="splunk-enrichment",
            summary=summary[:1000],
            status="executed",
            output={"source": source, "caveats": caveats},
        )
    except Exception:  # noqa: BLE001
        pass  # ledger is best-effort

    return {"status": "ok", "source": source, "llm_payload": payload, "caveats": caveats}
