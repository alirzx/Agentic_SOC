"""Map a live Splunk notable onto an Alert row.

Entity-risk can open a notable before fusion persisted the raw stash
row. This module pulls the fired event back from Splunk (search_name +
host) and copies severity, entities, MITRE, and the raw stash onto the
alert so the detail page is the real notable, not a title-only stub.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.alert import Alert
from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError, get_vault

logger = logging.getLogger(__name__)

_MITRE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

_TECHNIQUE_META: dict[str, tuple[str, str]] = {
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1049": ("Discovery", "System Network Connections Discovery"),
    "T1040": ("Discovery", "Network Sniffing"),
    "T1571": ("Command and Control", "Non-Standard Port"),
    "T1021": ("Lateral Movement", "Remote Services"),
    "T1021.001": ("Lateral Movement", "Remote Desktop Protocol"),
}

# Splunk ES correlation-search names → ATT&CK when the notable stash
# omitted annotations. These are the vendor rule mappings, not invented
# incident content.
_ES_RULE_MITRE: dict[str, tuple[str, ...]] = {
    "network - unapproved port activity detected - rule": ("T1046", "T1571"),
    "network - unapproved port activity detected": ("T1046", "T1571"),
}

_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
    "1": "info",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "critical",
}


def needs_hydrate(alert: Alert) -> bool:
    """True when the row is a title/host stub missing the Splunk stash."""
    if (alert.connector_type or "").lower() != "splunk":
        return False
    raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    if raw.get("dest_port") or raw.get("_raw") or raw.get("src") or raw.get("src_ip"):
        return False
    extra = alert.enrichment_data if isinstance(alert.enrichment_data, dict) else {}
    return not extra.get("splunk_hydrate_attempted")


def extract_mitre_ids(raw: dict[str, Any], title: str | None = None) -> list[str]:
    """Collect MITRE technique IDs from a notable row, then the ES catalog."""
    found: list[str] = []
    for key in (
        "annotations.mitre_attack",
        "orig_rule.annotations.mitre_attack",
        "mitre_attack",
        "mitre",
        "signature",
    ):
        _extend_ids(found, raw.get(key))
    annotations = raw.get("annotations")
    if isinstance(annotations, dict):
        _extend_ids(found, annotations.get("mitre_attack"))
    orig = raw.get("orig_rule")
    if isinstance(orig, dict):
        nested = orig.get("annotations")
        if isinstance(nested, dict):
            _extend_ids(found, nested.get("mitre_attack"))
    if not found and title:
        catalog = _ES_RULE_MITRE.get(title.strip().lower())
        if catalog:
            found.extend(catalog)
    deduped: list[str] = []
    seen: set[str] = set()
    for tid in found:
        key = tid.upper()
        if key not in seen:
            seen.add(key)
            deduped.append(key)
    return deduped


def mitre_attack_rows(technique_ids: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for tid in technique_ids:
        tactic, name = _TECHNIQUE_META.get(tid, ("", tid))
        rows.append({"tactic": tactic, "technique": name, "technique_id": tid})
    return rows


def iocs_from_raw(raw: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: Any) -> None:
        text = str(value).strip() if value not in (None, "") else ""
        if not text:
            return
        key = (kind, text.lower())
        if key in seen:
            return
        seen.add(key)
        out.append({"type": kind, "value": text})

    add("ip", raw.get("src") or raw.get("src_ip"))
    add("ip", raw.get("dest") if _looks_ip(raw.get("dest")) else raw.get("dest_ip"))
    add("host", raw.get("dvc") or raw.get("dest") or raw.get("host"))
    port = raw.get("dest_port")
    if port not in (None, ""):
        add("port", f"{raw.get('transport') or 'tcp'}/{port}")
    return out


def apply_notable(alert: Alert, envelope: dict[str, Any]) -> None:
    """Copy a normalized Splunk notable onto an existing Alert row."""
    raw = envelope.get("raw_event") if isinstance(envelope.get("raw_event"), dict) else envelope
    if not isinstance(raw, dict):
        raw = {}
    title = str(envelope.get("title") or raw.get("search_name") or alert.title)
    host = (
        envelope.get("hostname")
        or raw.get("dvc")
        or raw.get("dest")
        or raw.get("host")
    )
    src = envelope.get("src_ip") or raw.get("src") or raw.get("src_ip")
    port = raw.get("dest_port")
    transport = raw.get("transport") or "tcp"
    severity = str(envelope.get("severity") or "")
    if severity in _SEVERITY:
        alert.severity = _SEVERITY[severity]
    else:
        mapped = _SEVERITY.get(str(raw.get("urgency") or raw.get("severity") or "").strip().lower())
        if mapped:
            alert.severity = mapped
    description = str(envelope.get("description") or "").strip()
    if not description or description.startswith("Splunk notable"):
        description = _describe(title, host, src, port, transport)
    alert.title = title[:500]
    alert.description = description[:4000]
    alert.rule_name = title
    alert.rule_id = str(raw.get("search_name") or title)
    alert.connector_type = "splunk"
    alert.raw_event = raw
    hosts = [str(h) for h in (alert.affected_hosts or []) if h]
    if host and str(host) not in hosts:
        hosts.append(str(host))
    alert.affected_hosts = hosts
    ips = [str(i) for i in (alert.affected_ips or []) if i]
    if src and _looks_ip(src) and str(src) not in ips:
        ips.append(str(src))
    dest_ip = raw.get("dest_ip")
    if dest_ip and _looks_ip(dest_ip) and str(dest_ip) not in ips:
        ips.append(str(dest_ip))
    alert.affected_ips = ips
    techniques = extract_mitre_ids(raw, title)
    alert.mitre_techniques = techniques
    alert.mitre_tactics = [
        _TECHNIQUE_META[tid][0] for tid in techniques if tid in _TECHNIQUE_META and _TECHNIQUE_META[tid][0]
    ]
    event_id = envelope.get("external_id") or raw.get("source_guid") or raw.get("event_id")
    if event_id:
        ids = [str(x) for x in (alert.source_event_ids or [])]
        if str(event_id) not in ids:
            ids.append(str(event_id))
        alert.source_event_ids = ids
    created = envelope.get("created_at") or raw.get("_time")
    parsed = _parse_time(created)
    if parsed is not None:
        alert.event_time = parsed
        alert.first_seen = parsed
        alert.last_seen = parsed
    tags = [str(t) for t in (alert.tags or [])]
    for extra in ("splunk", "notable"):
        if extra not in tags:
            tags.append(extra)
    if port not in (None, "") and f"port:{port}" not in tags:
        tags.append(f"port:{port}")
    alert.tags = tags
    extra = dict(alert.enrichment_data or {})
    extra.update(
        {
            "iocs": iocs_from_raw(raw),
            "mitre_attack": mitre_attack_rows(techniques),
            "splunk_source_ref": str(event_id or alert.rule_id or ""),
            "splunk_hydrate_attempted": True,
        }
    )
    alert.enrichment_data = extra
    alert.priority = {"info": 10, "low": 30, "medium": 50, "high": 75, "critical": 95}.get(
        alert.severity, 50
    )
    alert.updated_at = datetime.now(UTC)


async def hydrate_alert(db: AsyncSession, alert: Alert) -> Alert:
    """Fetch the live Splunk notable and persist it onto ``alert`` when stubby."""
    if not needs_hydrate(alert):
        return alert
    title = (alert.title or alert.rule_name or "").strip()
    host = ""
    if alert.affected_hosts:
        host = str(alert.affected_hosts[0])
    raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    host = host or str(raw.get("host") or "")
    envelope = await fetch_notable(db, alert.tenant_id, title, host or None)
    if envelope is None:
        apply_notable(
            alert,
            {
                "title": title,
                "hostname": host,
                "raw_event": raw or {"search_name": title, "host": host},
            },
        )
    else:
        apply_notable(alert, envelope)
    await db.commit()
    await db.refresh(alert)
    return alert


async def fetch_notable(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    title: str,
    host: str | None,
) -> dict[str, Any] | None:
    """Ask the connectors service for the matching index=notable row."""
    if not title:
        return None
    result = await db.execute(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.connector_type == "splunk",
            Connector.is_enabled.is_(True),
        )
    )
    connector = result.scalars().first()
    if connector is None:
        return None
    try:
        auth = get_vault().decrypt_dict(connector.auth_config or {})
    except CredentialVaultError:
        logger.warning("splunk_notable.vault_failed tenant=%s", tenant_id)
        return None
    url = f"{settings.CONNECTORS_SERVICE_URL.rstrip('/')}/api/v1/connectors/splunk/lookup_notable"
    payload = {
        "auth_config": auth,
        "connector_config": connector.connector_config or {},
        "title": title,
        "host": host,
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(45.0)) as client:
            resp = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        logger.warning(
            "splunk_notable.unreachable err=%s",
            str(exc).replace("\r", " ").replace("\n", " ")[:240],
        )
        return None
    if resp.status_code >= 400:
        return None
    body = resp.json()
    row = body.get("notable") if isinstance(body, dict) else None
    return row if isinstance(row, dict) else None


def _extend_ids(found: list[str], value: Any) -> None:
    if value is None:
        return
    if isinstance(value, list):
        for item in value:
            _extend_ids(found, item)
        return
    if isinstance(value, dict):
        _extend_ids(found, value.get("id") or value.get("technique_id") or value.get("mitre_attack"))
        return
    text = str(value).strip()
    if not text:
        return
    if text.startswith("[") or text.startswith("{"):
        try:
            _extend_ids(found, json.loads(text))
            return
        except json.JSONDecodeError:
            pass
    found.extend(match.group(0).upper() for match in _MITRE_ID_RE.finditer(text))


def _describe(title: str, host: Any, src: Any, port: Any, transport: Any) -> str:
    bits = [title]
    if host:
        bits.append(f"on host {host}")
    if port not in (None, ""):
        bits.append(f"unapproved {transport} port {port}")
    if src:
        bits.append(f"source {src}")
    return ". ".join(bits) + "."


def _looks_ip(value: Any) -> bool:
    text = str(value or "")
    if text.count(".") != 3:
        return False
    parts = text.split(".")
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _parse_time(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
