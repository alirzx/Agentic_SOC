"""Promotion of ingest-normalized OCSF events into fusion RawAlerts.

Phase 3.1 (world-class program) closed the first of the two spine gaps the
reality audit exposed: ``services/ingest`` publishes normalized OCSF events to
``aisoc.raw_events`` and — before this module — **nothing consumed them**. The
fusion worker now subscribes to that topic and runs every message through
:func:`promote_normalized_event`.

Promotion policy (deterministic, no LLM, documented honestly):

* **Vendor-asserted findings are promoted.** Any event in the OCSF *Findings*
  category (``class_uid`` 2000–2999 — Security Finding, Detection Finding,
  etc.) is already an alert in the source product's judgment; dropping it on
  the floor would be silent data loss.
* **High/critical telemetry is promoted.** Non-finding events with
  ``severity_id >= 4`` (High / Critical / Fatal on the OCSF ladder) are
  promoted so a critical Okta or K8s event is never invisible to the SOC.
* **Everything else is NOT promoted.** Turning raw Medium-and-below telemetry
  into alerts is the job of the detection engine, not this bridge — promoting
  it here would destroy the alert-reduction property the fusion stage exists
  to provide.

Events whose ``tenant_id`` is not a UUID are skipped (the alert store keys
tenants by UUID; a non-UUID tenant header is a mis-configured connector, and
we log it rather than crash the consumer).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import structlog

from app.models.alert import AlertSeverity, RawAlert
from app.services.provenance import extract_provenance

logger = structlog.get_logger()

# OCSF category 2 = Findings (Security Finding 2001, Vulnerability Finding
# 2002, Compliance Finding 2003, Detection Finding 2004, ...).
_FINDINGS_CATEGORY = 2

# OCSF severity_id >= 4 means High(4) / Critical(5) / Fatal(6).
_PROMOTE_SEVERITY_FLOOR = 4

_SEVERITY_BY_ID: dict[int, AlertSeverity] = {
    6: AlertSeverity.CRITICAL,  # OCSF Fatal collapses onto our critical tier
    5: AlertSeverity.CRITICAL,
    4: AlertSeverity.HIGH,
    3: AlertSeverity.MEDIUM,
    2: AlertSeverity.LOW,
    1: AlertSeverity.INFO,
    0: AlertSeverity.MEDIUM,  # Unknown — median tier, never silently info
}


def _get_nested(obj: dict[str, Any], *path: str) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _first_file_hash(ocsf: dict[str, Any]) -> str | None:
    fingerprints = _get_nested(ocsf, "file", "fingerprints")
    if isinstance(fingerprints, list) and fingerprints:
        first = fingerprints[0]
        if isinstance(first, dict):
            value = first.get("value")
            if isinstance(value, str) and value:
                return value
    return None


def _mitre(ocsf: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Extract (tactics, techniques) from the ingest ATT&CK enrichment block."""
    tactics: list[str] = []
    techniques: list[str] = []
    block = ocsf.get("mitre_attck")
    if isinstance(block, list):
        for entry in block:
            if not isinstance(entry, dict):
                continue
            tid = entry.get("technique_id")
            if isinstance(tid, str) and tid and tid not in techniques:
                techniques.append(tid)
            names = entry.get("tactic_names")
            if isinstance(names, list):
                for name in names:
                    if isinstance(name, str) and name and name not in tactics:
                        tactics.append(name)
    unmapped = ocsf.get("unmapped") if isinstance(ocsf.get("unmapped"), dict) else {}
    for blob in (
        unmapped.get("annotations"),
        unmapped.get("mitre_attack"),
        ocsf.get("annotations"),
    ):
        if isinstance(blob, dict):
            blob = blob.get("mitre_attack")
        if isinstance(blob, list):
            for item in blob:
                tid = item if isinstance(item, str) else (item.get("id") if isinstance(item, dict) else None)
                if isinstance(tid, str) and tid and tid not in techniques:
                    techniques.append(tid)
    return tactics, techniques


def _title(ocsf: dict[str, Any], envelope_title: str | None = None) -> str:
    for val in (
        _get_nested(ocsf, "finding", "title"),
        _get_nested(ocsf, "unmapped", "search_name"),
        envelope_title,
        ocsf.get("message"),
        ocsf.get("activity_name"),
    ):
        if isinstance(val, str) and val.strip():
            return val.strip()[:500]
    class_name = ocsf.get("class_name") or "Security event"
    product = _get_nested(ocsf, "metadata", "product", "name")
    if isinstance(product, str) and product:
        return f"{class_name} from {product}"[:500]
    return str(class_name)[:500]


def _source(ocsf: dict[str, Any]) -> str:
    vendor = _get_nested(ocsf, "metadata", "product", "vendor_name")
    product = _get_nested(ocsf, "metadata", "product", "name")
    parts = [p for p in (vendor, product) if isinstance(p, str) and p]
    return " ".join(parts) or "ingest"


def _event_time(ocsf: dict[str, Any]) -> datetime | None:
    raw = ocsf.get("time")
    if isinstance(raw, str) and raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _as_int(value: Any) -> int | None:
    """Coerce JSON numbers (int/float/str) to int — Go maps often arrive as float."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def should_promote(ocsf: dict[str, Any]) -> bool:
    """Deterministic promotion decision — see module docstring for policy."""
    class_uid = _as_int(ocsf.get("class_uid"))
    if class_uid is not None and class_uid // 1000 == _FINDINGS_CATEGORY:
        return True
    severity_id = _as_int(ocsf.get("severity_id"))
    return severity_id is not None and severity_id >= _PROMOTE_SEVERITY_FLOOR


def promote_normalized_event(message: dict[str, Any]) -> RawAlert | None:
    """Convert one ``aisoc.raw_events`` message into a RawAlert, or ``None``.

    ``message`` is the JSON body ``services/ingest`` publishes — a
    ``NormalizedEvent`` with ``ocsf_event`` carrying the OCSF payload.
    Returns ``None`` when the event doesn't meet the promotion policy or the
    message is malformed (logged, never raised — one bad event must not wedge
    the consumer; the Phase 5 DLQ takes over from there).
    """
    ocsf = message.get("ocsf_event")
    if not isinstance(ocsf, dict):
        logger.warning("promoter.malformed_message", keys=sorted(message.keys()))
        return None

    if not should_promote(ocsf):
        return None

    tenant_raw = message.get("tenant_id") or ocsf.get("tenant_uid")
    try:
        tenant_id = uuid.UUID(str(tenant_raw))
    except (ValueError, TypeError):
        logger.warning("promoter.non_uuid_tenant", tenant_id=str(tenant_raw)[:64])
        return None

    severity_id = _as_int(ocsf.get("severity_id")) or 0
    severity = _SEVERITY_BY_ID.get(severity_id, AlertSeverity.MEDIUM)

    tactics, techniques = _mitre(ocsf)
    connector_id, connector_type, class_uid = extract_provenance(message, ocsf)

    finding_uid = _get_nested(ocsf, "finding", "uid")
    source_event_ids: list[str] = []
    if isinstance(finding_uid, str) and finding_uid.strip():
        source_event_ids.append(finding_uid.strip())

    # Detection rule identity — never the per-event finding uid. Putting the
    # unique event id in rule_id made every Splunk re-poll a new fingerprint.
    rule_id = None
    for candidate in (
        _get_nested(ocsf, "finding", "rule_id"),
        ocsf.get("rule_id"),
        _get_nested(ocsf, "unmapped", "search_name"),
    ):
        if isinstance(candidate, str) and candidate.strip() and candidate.strip() != (finding_uid or "").strip():
            rule_id = candidate.strip()
            break

    envelope_title = message.get("title")
    title = _title(ocsf, envelope_title if isinstance(envelope_title, str) else None)
    return RawAlert(
        tenant_id=tenant_id,
        source=_source(ocsf),
        title=title,
        description=str(ocsf.get("raw_data") or "")[:2000],
        severity=severity,
        src_ip=_get_nested(ocsf, "src_endpoint", "ip"),
        dst_ip=_get_nested(ocsf, "dst_endpoint", "ip"),
        hostname=(
            _get_nested(ocsf, "device", "name")
            or _get_nested(ocsf, "unmapped", "host")
        ),
        username=_get_nested(ocsf, "actor", "user", "name"),
        file_hash=_first_file_hash(ocsf),
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        raw_event=ocsf,
        event_time=_event_time(ocsf),
        connector_id=connector_id,
        connector_type=connector_type,
        ocsf_class_uid=class_uid,
        source_event_ids=source_event_ids,
        rule_id=rule_id,
        rule_name=title,
    )
