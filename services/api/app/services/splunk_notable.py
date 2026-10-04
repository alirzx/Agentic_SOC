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


def _is_ocsf_shape(raw: dict[str, Any]) -> bool:
    return "class_uid" in raw or "raw_data" in raw or "category_uid" in raw


def _unwrap_splunk_stash(raw: dict[str, Any]) -> dict[str, Any]:
    """Return the innermost Splunk notable stash from an alert.raw_event blob."""
    if not isinstance(raw, dict) or not raw:
        return {}
    nested = raw.get("splunk_notable")
    if isinstance(nested, dict) and (
        nested.get("annotations_mitre_attack")
        or nested.get("search_name")
        or nested.get("orig_rule_description")
    ):
        return nested
    if not _is_ocsf_shape(raw) and (
        raw.get("search_name") or raw.get("orig_rule_description") or raw.get("annotations_mitre_attack")
    ):
        return raw
    raw_data = raw.get("raw_data")
    if isinstance(raw_data, str) and raw_data.lstrip().startswith("{"):
        try:
            outer = json.loads(raw_data)
        except json.JSONDecodeError:
            outer = None
        if isinstance(outer, dict):
            inner = outer.get("raw_event")
            if isinstance(inner, dict):
                return inner
            if str(outer.get("source") or "").lower() == "splunk":
                return outer
    finding = raw.get("finding")
    if isinstance(finding, dict) and finding.get("uid"):
        return {"source_event_id": finding.get("uid"), "notable_id": finding.get("uid")}
    return {}


def _is_splunk_alert(alert: Alert) -> bool:
    if (alert.connector_type or "").lower() == "splunk":
        return True
    tags = alert.tags or []
    if any(str(t).lower() == "splunk" for t in tags):
        return True
    raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    meta = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    product = meta.get("product") if isinstance(meta.get("product"), dict) else {}
    if str(product.get("name") or "").lower() == "splunk":
        return True
    if str(product.get("vendor_name") or "").lower() == "splunk":
        return True
    raw_data = raw.get("raw_data")
    if isinstance(raw_data, str) and "splunk" in raw_data.lower():
        return True
    return False


def _annotation_present(blob: dict[str, Any]) -> bool:
    if blob.get("annotations_mitre_attack"):
        return True
    annotations = blob.get("annotations")
    if isinstance(annotations, dict) and annotations.get("mitre_attack"):
        return True
    if isinstance(annotations, str) and "mitre_attack" in annotations:
        return True
    return False


def _has_wide_annotation_fields(raw: dict[str, Any]) -> bool:
    """True when the stash already carries the wide Mission Control columns."""
    if _annotation_present(raw):
        return True
    return _annotation_present(_unwrap_splunk_stash(raw))


def needs_hydrate(alert: Alert) -> bool:
    """True when the row is missing Mission Control / wide annotation fields."""
    if not _is_splunk_alert(alert):
        return False
    raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    extra = alert.enrichment_data if isinstance(alert.enrichment_data, dict) else {}
    # Always retry until wide annotations land — a prior failed attempt must not
    # permanently skip (lookup used to fail on src-only entities).
    if not _has_wide_annotation_fields(raw):
        return True
    stash = _unwrap_splunk_stash(raw)
    if stash.get("orig_rule_description") and (stash.get("detection_id") or stash.get("notable_id")):
        return False
    return not extra.get("splunk_mc_hydrate_attempted")


def extract_mitre_ids(raw: dict[str, Any], title: str | None = None) -> list[str]:
    """Collect MITRE technique IDs from a notable row, then the ES catalog."""
    found: list[str] = []
    for key in (
        "annotations_mitre_attack",
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
    else:
        _extend_ids(found, annotations)
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
    src_port = raw.get("src_port")
    if src_port not in (None, ""):
        add("port", f"src/{src_port}")
    return out


_WIDE_RAW_KEYS = (
    "annotations_mitre_attack",
    "annotations",
    "annotations_analytic_story",
    "annotations_kill_chain_phases",
    "annotations_cis20",
    "annotations_nist",
    "annotations_data_source",
    "annotations_type",
    "annotations_type_list",
    "orig_rule_title",
    "orig_rule_description",
    "search_name",
    "detection_id",
    "notable_id",
    "source_event_id",
    "source_guid",
    "src",
    "src_ip",
    "dest",
    "dest_ip",
    "dest_port",
    "dvc",
    "host",
    "severity",
    "transport",
    "is_prohibited",
    "EventID",
    "Image",
    "Path",
    "user",
)


def _merge_stash_into_raw_event(existing: dict[str, Any], stash: dict[str, Any]) -> dict[str, Any]:
    """Keep OCSF wrapper (Raw tab) but surface wide Splunk fields at the top."""
    if not isinstance(existing, dict) or not _is_ocsf_shape(existing):
        return stash
    merged = dict(existing)
    merged["splunk_notable"] = stash
    for key in _WIDE_RAW_KEYS:
        value = stash.get(key)
        if value not in (None, ""):
            merged[key] = value
    raw_data = existing.get("raw_data")
    if isinstance(raw_data, str) and raw_data.lstrip().startswith("{"):
        try:
            outer = json.loads(raw_data)
        except json.JSONDecodeError:
            outer = None
        if isinstance(outer, dict):
            inner = outer.get("raw_event")
            if isinstance(inner, dict):
                outer["raw_event"] = {**inner, **stash}
            else:
                outer["raw_event"] = stash
            for key in ("annotations_mitre_attack", "annotations"):
                if stash.get(key) not in (None, ""):
                    outer[key] = stash.get(key)
            merged["raw_data"] = json.dumps(outer, ensure_ascii=False)
    return merged


def apply_notable(alert: Alert, envelope: dict[str, Any]) -> None:
    """Copy a normalized Splunk notable onto an existing Alert row."""
    raw = envelope.get("raw_event") if isinstance(envelope.get("raw_event"), dict) else envelope
    if not isinstance(raw, dict):
        raw = {}
    title = str(
        raw.get("search_name")
        or envelope.get("title")
        or raw.get("orig_rule_title")
        or alert.title
    )
    host = (
        envelope.get("hostname")
        or raw.get("dvc")
        or raw.get("dest")
        or raw.get("host")
        or raw.get("asset")
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
    orig_desc = str(raw.get("orig_rule_description") or "").strip()
    envelope_desc = str(envelope.get("description") or "").strip()
    if orig_desc:
        description = orig_desc
    elif envelope_desc and not envelope_desc.startswith("Splunk notable"):
        description = envelope_desc
    else:
        description = _describe(title, host, src, port, transport)
    alert.title = title[:500]
    alert.description = description[:4000]
    alert.rule_name = str(raw.get("orig_rule_title") or title)
    alert.rule_id = str(raw.get("detection_id") or raw.get("search_name") or title)
    alert.connector_type = "splunk"
    existing_raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    alert.raw_event = _merge_stash_into_raw_event(existing_raw, raw)
    hosts = [str(h) for h in (alert.affected_hosts or []) if h]
    if host and str(host) not in hosts:
        hosts.append(str(host))
    ips = [str(i) for i in (alert.affected_ips or []) if i]
    if src and _looks_ip(src) and str(src) not in ips:
        ips.append(str(src))
    dest_ip = raw.get("dest_ip")
    if dest_ip and _looks_ip(dest_ip) and str(dest_ip) not in ips:
        ips.append(str(dest_ip))
    alert.affected_ips = ips
    users = [str(u) for u in (getattr(alert, "affected_users", None) or []) if u]
    if src and not _looks_ip(src):
        if str(src) not in hosts:
            hosts.append(str(src))
        if str(src) not in users:
            users.append(str(src))
    alert.affected_hosts = hosts
    if hasattr(alert, "affected_users"):
        alert.affected_users = users
    techniques = extract_mitre_ids(raw, title)
    alert.mitre_techniques = techniques
    alert.mitre_tactics = [
        _TECHNIQUE_META[tid][0] for tid in techniques if tid in _TECHNIQUE_META and _TECHNIQUE_META[tid][0]
    ]
    event_id = (
        envelope.get("external_id")
        or raw.get("notable_id")
        or raw.get("source_guid")
        or raw.get("source_event_id")
        or raw.get("detection_id")
        or raw.get("event_id")
    )
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
            "splunk_mc_hydrate_attempted": True,
            "splunk_wide_reenrich_attempted": True,
            "splunk_wide_reenrich_at": datetime.now(UTC).isoformat(),
            "splunk_wide_reenrich_ok": _annotation_present(raw) or bool(techniques),
        }
    )
    alert.enrichment_data = extra
    alert.priority = {"info": 10, "low": 30, "medium": 50, "high": 75, "critical": 95}.get(
        alert.severity, 50
    )
    alert.updated_at = datetime.now(UTC)


async def hydrate_alert(
    db: AsyncSession,
    alert: Alert,
    *,
    force: bool = False,
    commit: bool = True,
) -> Alert:
    """Fetch the live Splunk notable and persist it onto ``alert`` when stubby."""
    if not force and not needs_hydrate(alert):
        return alert
    raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    stash = _unwrap_splunk_stash(raw)
    title = (
        alert.title
        or alert.rule_name
        or str(stash.get("search_name") or raw.get("message") or "")
    ).strip()
    entity = ""
    if alert.affected_hosts:
        entity = str(alert.affected_hosts[0])
    entity = (
        entity
        or str(stash.get("dvc") or "")
        or str(stash.get("dest") or "")
        or str(stash.get("host") or "")
        or str(stash.get("src") or "")
        or str(stash.get("src_ip") or "")
    )
    if not entity:
        src_ep = raw.get("src_endpoint") if isinstance(raw.get("src_endpoint"), dict) else {}
        entity = str(src_ep.get("ip") or src_ep.get("hostname") or "")
    notable_id = str(
        stash.get("source_event_id")
        or stash.get("notable_id")
        or stash.get("source_guid")
        or ""
    )
    if not notable_id and isinstance(raw.get("finding"), dict):
        notable_id = str(raw["finding"].get("uid") or "")
    envelope = await fetch_notable(
        db,
        alert.tenant_id,
        title,
        entity or None,
        notable_id=notable_id or None,
    )
    if envelope is None:
        # Do not permanently burn the attempt when Splunk returned nothing —
        # leave the flag unset for non-force so a later retry can succeed.
        extra = dict(alert.enrichment_data or {})
        extra["splunk_wide_reenrich_last_miss_at"] = datetime.now(UTC).isoformat()
        if force:
            extra["splunk_wide_reenrich_attempted"] = True
            extra["splunk_wide_reenrich_ok"] = False
        alert.enrichment_data = extra
        alert.updated_at = datetime.now(UTC)
    else:
        apply_notable(alert, envelope)
    if commit:
        await db.commit()
        await db.refresh(alert)
    return alert


async def reenrich_tenant_splunk_alerts(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    limit: int = 500,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Re-fetch wide Splunk notable fields for existing alerts and sync case MITRE.

    Targets Splunk-sourced alerts missing ``annotations_mitre_attack`` / nested
    MITRE annotations (the columns added to the Mission Control SPL table).
    """
    import asyncio

    from sqlalchemy import String, cast, or_

    lim = max(1, min(int(limit), 5000))
    # Include OCSF-wrapped Splunk findings that never got connector_type=splunk.
    q = (
        select(Alert)
        .where(Alert.tenant_id == tenant_id)
        .where(
            or_(
                Alert.connector_type == "splunk",
                Alert.tags.contains(["splunk"]),
                cast(Alert.raw_event, String).ilike("%splunk%"),
            )
        )
        .order_by(Alert.created_at.desc())
        .limit(lim * 2)
    )
    rows = (await db.execute(q)).scalars().all()
    candidates = [a for a in rows if _is_splunk_alert(a) and (force or needs_hydrate(a))][:lim]
    enriched = 0
    skipped = 0
    failed = 0
    timed_out = 0
    sample_ids: list[str] = []
    total = len(candidates)
    logger.info(
        "splunk_notable.reenrich_start scanned=%s candidates=%s force=%s",
        len(rows),
        total,
        force,
    )
    for idx, alert in enumerate(candidates, start=1):
        if dry_run:
            enriched += 1
            if len(sample_ids) < 20:
                sample_ids.append(str(alert.id))
            continue
        before = _has_wide_annotation_fields(
            alert.raw_event if isinstance(alert.raw_event, dict) else {}
        )
        try:
            # Cap each Splunk round-trip so one stuck job can't wedge the whole run.
            await asyncio.wait_for(
                hydrate_alert(db, alert, force=True, commit=False),
                timeout=45.0,
            )
            after = _has_wide_annotation_fields(
                alert.raw_event if isinstance(alert.raw_event, dict) else {}
            )
            if after and (not before or alert.mitre_techniques):
                enriched += 1
                if len(sample_ids) < 20:
                    sample_ids.append(str(alert.id))
            else:
                skipped += 1
        except asyncio.TimeoutError:
            timed_out += 1
            failed += 1
            logger.warning(
                "splunk_notable.reenrich_timeout alert=%s idx=%s/%s",
                str(alert.id).replace("\r", " ").replace("\n", " ")[:64],
                idx,
                total,
            )
        except Exception as exc:  # noqa: BLE001
            failed += 1
            logger.warning(
                "splunk_notable.reenrich_failed alert=%s err=%s",
                str(alert.id).replace("\r", " ").replace("\n", " ")[:64],
                str(exc).replace("\r", " ").replace("\n", " ")[:200],
            )
        if idx % 10 == 0 or idx == total:
            await db.commit()
            logger.info(
                "splunk_notable.reenrich_progress idx=%s/%s enriched=%s skipped=%s failed=%s",
                idx,
                total,
                enriched,
                skipped,
                failed,
            )
            print(
                f"[reenrich] {idx}/{total} enriched={enriched} skipped={skipped} "
                f"failed={failed} timed_out={timed_out}",
                flush=True,
            )

    cases_updated = 0
    if not dry_run:
        await db.commit()
        if enriched:
            cases_updated = await _sync_case_mitre_from_alerts(db, tenant_id=tenant_id)
            await db.commit()

    return {
        "scanned": len(rows),
        "candidates": len(candidates),
        "enriched": enriched,
        "skipped": skipped,
        "failed": failed,
        "timed_out": timed_out,
        "cases_updated": cases_updated,
        "sample_alert_ids": sample_ids,
        "dry_run": dry_run,
        "force": force,
    }


async def _sync_case_mitre_from_alerts(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
) -> int:
    """Union MITRE techniques from linked alerts onto open aisoc_cases."""
    from sqlalchemy import text

    result = await db.execute(
        text(
            """
            WITH alert_tech AS (
              SELECT c.id AS case_id,
                     COALESCE(
                       (
                         SELECT jsonb_agg(DISTINCT upper(t))
                           FROM alerts a
                           CROSS JOIN LATERAL jsonb_array_elements_text(
                             CASE
                               WHEN jsonb_typeof(COALESCE(a.mitre_techniques, '[]'::jsonb)) = 'array'
                               THEN COALESCE(a.mitre_techniques, '[]'::jsonb)
                               ELSE '[]'::jsonb
                             END
                           ) AS t(t)
                          WHERE a.tenant_id = :tid
                            AND (
                              a.case_id = c.id
                              OR a.id = ANY(COALESCE(c.alert_ids, ARRAY[]::uuid[]))
                            )
                            AND t ~* '^T[0-9]'
                       ),
                       '[]'::jsonb
                     ) AS techniques
                FROM aisoc_cases c
               WHERE c.tenant_id = :tid
                 AND c.status NOT IN ('closed')
            )
            UPDATE aisoc_cases c
               SET mitre_techniques = a.techniques,
                   updated_at = now()
              FROM alert_tech a
             WHERE c.id = a.case_id
               AND a.techniques <> '[]'::jsonb
               AND COALESCE(c.mitre_techniques, '[]'::jsonb) IS DISTINCT FROM a.techniques
            """
        ).bindparams(tid=tenant_id)
    )
    return int(result.rowcount or 0)


async def fetch_notable(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    title: str,
    host: str | None,
    notable_id: str | None = None,
) -> dict[str, Any] | None:
    """Ask the connectors service for the matching index=agentic* notable row."""
    if not (title or "").strip() and not (notable_id or "").strip():
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
        "title": title or "",
        "host": host,
        "notable_id": notable_id,
    }
    try:
        # Keep under the bulk re-enrich per-alert wait_for (45s).
        async with httpx.AsyncClient(timeout=httpx.Timeout(40.0, connect=5.0)) as client:
            resp = await client.post(url, json=payload)
    except httpx.TimeoutException as exc:
        logger.warning(
            "splunk_notable.timeout err=%s",
            str(exc).replace("\r", " ").replace("\n", " ")[:240],
        )
        return None
    except httpx.HTTPError as exc:
        logger.warning(
            "splunk_notable.unreachable err=%s",
            str(exc).replace("\r", " ").replace("\n", " ")[:240],
        )
        return None
    if resp.status_code >= 400:
        logger.warning(
            "splunk_notable.lookup_http status=%s body=%s",
            resp.status_code,
            resp.text.replace("\r", " ").replace("\n", " ")[:200],
        )
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
