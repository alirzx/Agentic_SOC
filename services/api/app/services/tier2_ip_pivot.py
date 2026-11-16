"""Tier-2 Investigate preflight: src/dest IP check → 24h siblings → Case.

Analyst workflow this encodes:

1. Resolve ``src_ip`` / ``dest_ip`` from llm_payload, raw_event, affected_ips, iocs
2. Find other tenant alerts in the last 24h that share the **dest_ip**
   (primary) or ``src_ip`` (secondary)
3. Collect seed + siblings into one ``aisoc_cases`` campaign case
4. Return pivot context so Investigate / case report treat them as one incident
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.campaign_case import (
    campaign_case_title,
    campaign_tags,
    infer_attack_theme,
    primary_campaign_key,
)

logger = structlog.get_logger()

_SIBLING_CAP = 64
_DEFAULT_HOURS = 24

# Canonical Tier-2 steps shown in the Alert Runbook tab (order matters).
TIER2_RUNBOOK_STEPS: tuple[dict[str, str], ...] = (
    {
        "action_name": "tier2_extract_ips",
        "label": "1. Extract src_ip / dest_ip",
    },
    {
        "action_name": "tier2_find_related",
        "label": "2. Find related alerts (24h / dest_ip)",
    },
    {
        "action_name": "tier2_aggregate_case",
        "label": "3. Aggregate into one Case",
    },
    {
        "action_name": "tier2_investigate",
        "label": "4. Investigate on Case",
    },
    {
        "action_name": "tier2_case_report",
        "label": "5. Case report scope",
    },
)
_IP_RE = re.compile(
    r"^(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
    r"|"
    r"[0-9a-fA-F:]+"  # loose IPv6
    r")$"
)
_NONE = {"", "none", "null", "n/a", "-", "—", "unknown", "0.0.0.0", "::"}


@dataclass
class ExtractedIps:
    src_ips: list[str] = field(default_factory=list)
    dest_ips: list[str] = field(default_factory=list)

    @property
    def all_ips(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for value in [*self.dest_ips, *self.src_ips]:
            key = value.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(value)
        return out


@dataclass
class Tier2PivotResult:
    src_ips: list[str]
    dest_ips: list[str]
    related_alert_ids: list[str]
    case_id: str | None
    case_created: bool
    case_extended: bool
    window_hours: int
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src_ips": self.src_ips,
            "dest_ips": self.dest_ips,
            "related_alert_ids": self.related_alert_ids,
            "case_id": self.case_id,
            "case_created": self.case_created,
            "case_extended": self.case_extended,
            "window_hours": self.window_hours,
            "notes": self.notes,
            "related_count": max(0, len(self.related_alert_ids) - 1),
        }


def _clean_ip(value: Any) -> str | None:
    text_val = str(value or "").strip()
    if not text_val or text_val.lower() in _NONE:
        return None
    # Strip brackets / CIDR suffix for matching.
    text_val = text_val.strip("[]")
    if "/" in text_val:
        text_val = text_val.split("/", 1)[0]
    if not _IP_RE.match(text_val):
        return None
    return text_val


def _add_ip(bucket: list[str], seen: set[str], value: Any) -> None:
    cleaned = _clean_ip(value)
    if cleaned is None:
        return
    key = cleaned.lower()
    if key in seen:
        return
    seen.add(key)
    bucket.append(cleaned)


def _walk_dict_ips(payload: dict[str, Any], src: list[str], dest: list[str], seen_s: set[str], seen_d: set[str]) -> None:
    src_keys = {"src_ip", "src", "source_ip", "client_ip", "attacker_ip", "srcip"}
    dest_keys = {"dest_ip", "dst_ip", "dest", "destination_ip", "dst", "server_ip", "destip", "dstip"}
    for key, value in payload.items():
        lk = str(key).lower()
        if lk in src_keys:
            _add_ip(src, seen_s, value)
        elif lk in dest_keys:
            _add_ip(dest, seen_d, value)


def extract_alert_ips(alert: Any) -> ExtractedIps:
    """Pull src/dest IPs from every common alert surface."""
    src: list[str] = []
    dest: list[str] = []
    seen_s: set[str] = set()
    seen_d: set[str] = set()

    def _get(name: str) -> Any:
        if isinstance(alert, dict):
            return alert.get(name)
        return getattr(alert, name, None)

    for item in _get("affected_ips") or []:
        if isinstance(item, dict):
            _add_ip(src, seen_s, item.get("value") or item.get("ip"))
        else:
            _add_ip(src, seen_s, item)

    for blob in (_get("llm_payload"), _get("raw_event"), _get("enrichment_data")):
        if isinstance(blob, dict):
            _walk_dict_ips(blob, src, dest, seen_s, seen_d)
            nested = blob.get("raw_event") or blob.get("raw_data") or blob.get("event")
            if isinstance(nested, dict):
                _walk_dict_ips(nested, src, dest, seen_s, seen_d)

    for ioc in _get("iocs") or []:
        if not isinstance(ioc, dict):
            continue
        kind = str(ioc.get("type") or ioc.get("kind") or "").lower()
        if kind in {"ip", "ipv4", "ipv6", "address"}:
            # Untyped IOC IPs go to dest first (victim/target bias for Tier-2).
            _add_ip(dest, seen_d, ioc.get("value") or ioc.get("ip"))

    # If dest empty but we only have one IP family in src from affected_ips,
    # keep src — Tier-2 still pivots on whatever we have.
    return ExtractedIps(src_ips=src, dest_ips=dest)


async def backfill_affected_ips(
    db: AsyncSession,
    *,
    alert_id: uuid.UUID,
    tenant_id: uuid.UUID,
    ips: ExtractedIps,
) -> None:
    """Persist extracted IPs onto ``affected_ips`` when the column is empty."""
    if not ips.all_ips:
        return
    await db.execute(
        text(
            """
            UPDATE alerts
               SET affected_ips = CAST(:ips AS JSONB),
                   updated_at = NOW()
             WHERE id = :id
               AND tenant_id = :tid
               AND (
                     affected_ips IS NULL
                  OR affected_ips = '[]'::jsonb
                  OR jsonb_typeof(affected_ips) <> 'array'
               )
            """
        ).bindparams(
            id=alert_id,
            tid=tenant_id,
            ips=json.dumps(ips.all_ips),
        )
    )


async def find_related_alert_ids(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    seed_id: uuid.UUID,
    ips: ExtractedIps,
    hours: int = _DEFAULT_HOURS,
    limit: int = _SIBLING_CAP,
) -> list[uuid.UUID]:
    """Return seed + sibling alert IDs sharing dest (preferred) or src IP."""
    pivot_ips = ips.dest_ips or ips.src_ips
    if not pivot_ips:
        return [seed_id]
    since = datetime.now(UTC) - timedelta(hours=max(1, hours))
    found: list[uuid.UUID] = [seed_id]
    seen = {seed_id}
    # Prefer dest matches; then src. Query each IP separately to keep SQL simple.
    for role, values in (("dest", ips.dest_ips), ("src", ips.src_ips if not ips.dest_ips else ips.src_ips)):
        del role  # documented for readers; matching is unified below
        for ip in values:
            if len(found) >= limit + 1:
                break
            rows = (
                await db.execute(
                    text(
                        """
                        SELECT id FROM alerts
                         WHERE tenant_id = :tid
                           AND created_at >= :since
                           AND id <> :seed
                           AND COALESCE(disposition, '') NOT IN (
                                 'false_positive', 'benign', 'benign_true_positive'
                           )
                           AND (
                                 COALESCE(affected_ips, '[]'::jsonb) @> to_jsonb(ARRAY[CAST(:ip AS text)])
                              OR COALESCE(raw_event->>'src_ip', '') = CAST(:ip AS text)
                              OR COALESCE(raw_event->>'src', '') = CAST(:ip AS text)
                              OR COALESCE(raw_event->>'dest_ip', '') = CAST(:ip AS text)
                              OR COALESCE(raw_event->>'dst_ip', '') = CAST(:ip AS text)
                              OR COALESCE(raw_event->>'dest', '') = CAST(:ip AS text)
                              OR COALESCE(llm_payload->>'src_ip', '') = CAST(:ip AS text)
                              OR COALESCE(llm_payload->>'src', '') = CAST(:ip AS text)
                              OR COALESCE(llm_payload->>'dest_ip', '') = CAST(:ip AS text)
                              OR COALESCE(llm_payload->>'dst_ip', '') = CAST(:ip AS text)
                              OR COALESCE(llm_payload->>'dest', '') = CAST(:ip AS text)
                              OR EXISTS (
                                    SELECT 1
                                      FROM jsonb_array_elements(
                                             CASE WHEN jsonb_typeof(COALESCE(iocs, '[]'::jsonb)) = 'array'
                                                  THEN COALESCE(iocs, '[]'::jsonb)
                                                  ELSE '[]'::jsonb END
                                           ) elem
                                     WHERE lower(COALESCE(elem->>'type', elem->>'kind', ''))
                                           IN ('ip', 'ipv4', 'ipv6', 'address')
                                       AND COALESCE(elem->>'value', elem->>'ip', '') = CAST(:ip AS text)
                              )
                           )
                         ORDER BY created_at DESC
                         LIMIT :lim
                        """
                    ).bindparams(
                        tid=tenant_id,
                        since=since,
                        seed=seed_id,
                        ip=ip,
                        lim=limit,
                    )
                )
            ).fetchall()
            for row in rows:
                aid = row[0]
                if aid in seen:
                    continue
                seen.add(aid)
                found.append(aid)
                if len(found) >= limit + 1:
                    break
    return found


async def _load_related_summaries(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_ids: list[uuid.UUID],
) -> list[dict[str, Any]]:
    if not alert_ids:
        return []
    rows = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, disposition, status,
                       affected_ips, llm_payload, raw_event, created_at
                  FROM alerts
                 WHERE tenant_id = :tid
                   AND id = ANY(CAST(:ids AS UUID[]))
                 ORDER BY created_at DESC
                """
            ).bindparams(tid=tenant_id, ids=[str(x) for x in alert_ids])
        )
    ).mappings().all()
    out: list[dict[str, Any]] = []
    for row in rows:
        ips = extract_alert_ips(dict(row))
        out.append(
            {
                "id": str(row["id"]),
                "title": row["title"],
                "severity": row["severity"],
                "disposition": row["disposition"],
                "status": row["status"],
                "src_ips": ips.src_ips,
                "dest_ips": ips.dest_ips,
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            }
        )
    return out


async def aggregate_into_case(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    seed: Any,
    alert_ids: list[uuid.UUID],
    ips: ExtractedIps,
) -> tuple[uuid.UUID, bool, bool]:
    """Create or extend an open Tier-2 / campaign case. Returns (case_id, created, extended)."""
    seed_id = seed.id if hasattr(seed, "id") else uuid.UUID(str(seed["id"]))
    existing_case = getattr(seed, "case_id", None) if hasattr(seed, "case_id") else None
    title = str(getattr(seed, "title", None) or (seed.get("title") if isinstance(seed, dict) else "") or "IP campaign")
    severity = str(getattr(seed, "severity", None) or "medium")
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "medium"
    mitre = list(getattr(seed, "mitre_techniques", None) or [])
    theme = infer_attack_theme(title=title, mitre_techniques=mitre)
    entities: list[tuple[str, str]] = [("ip", ip) for ip in ips.dest_ips[:3]] or [("ip", ip) for ip in ips.src_ips[:3]]
    camp_key = primary_campaign_key(theme, entities) or f"tier2-ip|{seed_id}"
    # Pivot cases are multi-alert by construction when siblings exist; default
    # to campaign framing — caller may override title below for pivot clarity.
    case_title = campaign_case_title(theme, entities, linked_alert_count=2)
    if ips.dest_ips:
        case_title = f"Tier-2 dest_ip pivot · {', '.join(ips.dest_ips[:2])}"[:500]
    elif ips.src_ips:
        case_title = f"Tier-2 src_ip pivot · {', '.join(ips.src_ips[:2])}"[:500]
    tags = campaign_tags(
        theme=theme,
        campaign_key=camp_key,
        source="tier2-investigate",
        linked_alert_count=2,
    )
    tags["tier2_ip_pivot"] = True
    tags["pivot_dest_ips"] = ips.dest_ips[:8]
    tags["pivot_src_ips"] = ips.src_ips[:8]
    now = datetime.now(UTC)
    since = now - timedelta(hours=_DEFAULT_HOURS)

    case_id: uuid.UUID | None = existing_case if isinstance(existing_case, uuid.UUID) else None
    created = False
    extended = False

    if case_id is None:
        row = (
            await db.execute(
                text(
                    """
                    SELECT id, alert_ids FROM aisoc_cases
                     WHERE tenant_id = :tid
                       AND status NOT IN ('resolved', 'closed')
                       AND opened_at >= :since
                       AND (
                             tags->>'campaign_key' = :ckey
                          OR tags->>'tier2_ip_pivot' = 'true'
                       )
                       AND (
                             tags->>'campaign_key' = :ckey
                          OR CAST(tags->'pivot_dest_ips' AS text) LIKE :dest_like
                          OR CAST(tags->'pivot_src_ips' AS text) LIKE :src_like
                       )
                     ORDER BY opened_at ASC
                     LIMIT 1
                    """
                ).bindparams(
                    tid=tenant_id,
                    since=since,
                    ckey=camp_key,
                    dest_like=f"%{ips.dest_ips[0]}%" if ips.dest_ips else "%__none__%",
                    src_like=f"%{ips.src_ips[0]}%" if ips.src_ips else "%__none__%",
                )
            )
        ).fetchone()
        if row:
            case_id = row[0]
            prior = list(row[1] or [])
            merged = list(dict.fromkeys([*prior, *[str(x) for x in alert_ids]]))
            await db.execute(
                text(
                    """
                    UPDATE aisoc_cases
                       SET alert_ids = CAST(:alert_ids AS UUID[]),
                           tags = COALESCE(tags, '{}'::jsonb) || CAST(:tags AS JSONB),
                           updated_at = :now
                     WHERE id = :id AND tenant_id = :tid
                    """
                ).bindparams(
                    id=case_id,
                    tid=tenant_id,
                    alert_ids=merged,
                    tags=json.dumps(tags),
                    now=now,
                )
            )
            extended = True
        else:
            case_id = uuid.uuid4()
            description = (
                "Tier-2 Investigate IP pivot case.\n"
                f"dest_ips: {', '.join(ips.dest_ips) or '(none)'}\n"
                f"src_ips: {', '.join(ips.src_ips) or '(none)'}\n"
                f"Linked alerts (24h): {len(alert_ids)}\n"
                f"Seed: {title}\n"
            )
            await db.execute(
                text(
                    """
                    INSERT INTO aisoc_cases (
                        id, tenant_id, title, description, severity, status,
                        alert_ids, tags, opened_at, created_at, updated_at, created_by
                    ) VALUES (
                        :id, :tid, :title, :description, :severity, 'investigating',
                        CAST(:alert_ids AS UUID[]), CAST(:tags AS JSONB),
                        :now, :now, :now, 'tier2-investigate'
                    )
                    """
                ).bindparams(
                    id=case_id,
                    tid=tenant_id,
                    title=case_title,
                    description=description,
                    severity=severity,
                    alert_ids=[str(x) for x in alert_ids],
                    tags=json.dumps(tags),
                    now=now,
                )
            )
            created = True
    else:
        # Seed already on a case — union siblings into it.
        prior_row = (
            await db.execute(
                text(
                    """
                    SELECT alert_ids FROM aisoc_cases
                     WHERE id = :id AND tenant_id = :tid
                    """
                ).bindparams(id=case_id, tid=tenant_id)
            )
        ).fetchone()
        prior = list(prior_row[0] or []) if prior_row else []
        merged = list(dict.fromkeys([*prior, *[str(x) for x in alert_ids]]))
        if len(merged) > len(prior):
            extended = True
        await db.execute(
            text(
                """
                UPDATE aisoc_cases
                   SET alert_ids = CAST(:alert_ids AS UUID[]),
                       tags = COALESCE(tags, '{}'::jsonb) || CAST(:tags AS JSONB),
                       status = CASE WHEN status IN ('new','triaging') THEN 'investigating' ELSE status END,
                       updated_at = :now
                 WHERE id = :id AND tenant_id = :tid
                """
            ).bindparams(
                id=case_id,
                tid=tenant_id,
                alert_ids=merged,
                tags=json.dumps(tags),
                now=now,
            )
        )

    assert case_id is not None
    await db.execute(
        text(
            """
            UPDATE alerts
               SET case_id = :cid,
                   status = CASE WHEN status IN ('new','triaging') THEN 'in_progress' ELSE status END,
                   tags = CASE
                       WHEN jsonb_typeof(COALESCE(tags, '[]'::jsonb)) = 'array'
                       THEN COALESCE(tags, '[]'::jsonb) || CAST(:tag AS JSONB)
                       ELSE CAST(:tag AS JSONB)
                   END,
                   updated_at = :now
             WHERE tenant_id = :tid
               AND id = ANY(CAST(:ids AS UUID[]))
            """
        ).bindparams(
            cid=case_id,
            tid=tenant_id,
            ids=[str(x) for x in alert_ids],
            tag=json.dumps(["tier2-ip-pivot", f"case:{case_id}"]),
            now=now,
        )
    )
    return case_id, created, extended


async def _emit_tier2_step(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    run_token: str,
    action_name: str,
    summary: str,
    status: str,
    detail: str | None = None,
    output_payload: dict[str, Any] | None = None,
) -> None:
    """One visible Runbook ledger line for a Tier-2 step (always shown)."""
    from app.services.runbook.recorder import record_event

    payload = dict(output_payload or {})
    payload["run_token"] = run_token
    payload["tier2"] = True
    payload["has_result"] = status in {"recorded", "executed"}
    await record_event(
        db,
        tenant_id=tenant_id,
        subject_type="alert",
        subject_id=alert_id,
        stage="investigate",
        kind="enrichment",
        summary=summary[:1000],
        detail=detail,
        status=status,
        actor_type="system",
        actor_label="tier2-investigate",
        action_name=action_name,
        output_payload=payload,
        idempotency_key=f"tier2:{alert_id}:{action_name}:{run_token}",
    )


async def persist_tier2_snapshot(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    steps: list[dict[str, Any]],
    pivot: dict[str, Any] | None = None,
) -> None:
    """Always persist Tier-2 outcomes on the alert (works even if Runbook ledger is off)."""
    snapshot = {
        "tier2_runbook": {
            "ran_at": datetime.now(UTC).isoformat(),
            "steps": steps,
            "pivot": pivot or {},
        }
    }
    await db.execute(
        text(
            """
            UPDATE alerts
               SET enrichment_data = COALESCE(enrichment_data, '{}'::jsonb)
                                   || CAST(:payload AS jsonb),
                   updated_at = NOW()
             WHERE id = :id AND tenant_id = :tid
            """
        ).bindparams(
            id=alert_id,
            tid=tenant_id,
            payload=json.dumps(snapshot),
        )
    )


def load_tier2_snapshot_from_alert(alert: Any) -> dict[str, Any] | None:
    enrichment = getattr(alert, "enrichment_data", None) if not isinstance(alert, dict) else alert.get("enrichment_data")
    if not isinstance(enrichment, dict):
        return None
    snap = enrichment.get("tier2_runbook")
    return snap if isinstance(snap, dict) else None



async def persist_tier2_snapshot(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    steps: list[dict[str, Any]],
    pivot: dict[str, Any] | None = None,
) -> None:
    """Always persist Tier-2 outcomes on the alert (works even if Runbook ledger is off)."""
    snapshot = {
        "tier2_runbook": {
            "ran_at": datetime.now(UTC).isoformat(),
            "steps": steps,
            "pivot": pivot or {},
        }
    }
    await db.execute(
        text(
            """
            UPDATE alerts
               SET enrichment_data = COALESCE(enrichment_data, '{}'::jsonb)
                                   || CAST(:payload AS jsonb),
                   updated_at = NOW()
             WHERE id = :id AND tenant_id = :tid
            """
        ).bindparams(
            id=alert_id,
            tid=tenant_id,
            payload=json.dumps(snapshot),
        )
    )


def load_tier2_snapshot_from_alert(alert: Any) -> dict[str, Any] | None:
    enrichment = (
        getattr(alert, "enrichment_data", None)
        if not isinstance(alert, dict)
        else alert.get("enrichment_data")
    )
    if not isinstance(enrichment, dict):
        return None
    snap = enrichment.get("tier2_runbook")
    return snap if isinstance(snap, dict) else None


async def emit_tier2_runbook_steps(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    run_token: str,
    ips: ExtractedIps,
    related_ids: list[uuid.UUID],
    related_summaries: list[dict[str, Any]],
    case_id: uuid.UUID | None,
    created: bool,
    extended: bool,
    hours: int,
    investigate_queued: bool,
) -> list[dict[str, Any]]:
    """Emit all five Tier-2 steps with explicit hit/miss outcomes for the UI."""
    steps_out: list[dict[str, Any]] = []
    related_count = max(0, len(related_ids) - 1)
    label_by_action = {item["action_name"]: item["label"] for item in TIER2_RUNBOOK_STEPS}

    if ips.all_ips:
        s1_status = "recorded"
        s1_summary = (
            f"Result: src_ip=[{', '.join(ips.src_ips) or '—'}] · "
            f"dest_ip=[{', '.join(ips.dest_ips) or '—'}]"
        )
    else:
        s1_status = "skipped"
        s1_summary = (
            "Result: empty — no src_ip/dest_ip found in llm_payload, raw_event, "
            "affected_ips, or IOCs"
        )
    s1_detail = json.dumps({"src_ips": ips.src_ips, "dest_ips": ips.dest_ips})
    await _emit_tier2_step(
        db,
        tenant_id=tenant_id,
        alert_id=alert_id,
        run_token=run_token,
        action_name="tier2_extract_ips",
        summary=s1_summary,
        status=s1_status,
        detail=s1_detail,
        output_payload={"src_ips": ips.src_ips, "dest_ips": ips.dest_ips},
    )
    steps_out.append(
        {
            "action_name": "tier2_extract_ips",
            "label": label_by_action["tier2_extract_ips"],
            "status": s1_status,
            "summary": s1_summary,
            "detail": s1_detail,
        }
    )

    if not ips.all_ips:
        s2_status = "skipped"
        s2_summary = "Result: skipped — no IP available to search"
    elif related_count > 0:
        s2_status = "recorded"
        titles = [
            str(s.get("title") or s.get("id"))
            for s in related_summaries
            if str(s.get("id")) != str(alert_id)
        ]
        s2_summary = (
            f"Result: {related_count} related alert(s) in {hours}h "
            f"(dest preferred, then src) — e.g. {', '.join(titles[:3]) or '—'}"
        )
    else:
        s2_status = "skipped"
        s2_summary = (
            f"Result: empty — no other alerts with the same dest_ip/src_ip "
            f"in the last {hours}h"
        )
    s2_detail = json.dumps(
        {"related_alert_ids": [str(x) for x in related_ids], "related_count": related_count}
    )
    await _emit_tier2_step(
        db,
        tenant_id=tenant_id,
        alert_id=alert_id,
        run_token=run_token,
        action_name="tier2_find_related",
        summary=s2_summary,
        status=s2_status,
        detail=s2_detail,
        output_payload={
            "related_alert_ids": [str(x) for x in related_ids],
            "related_count": related_count,
            "related_alerts": related_summaries[:20],
        },
    )
    steps_out.append(
        {
            "action_name": "tier2_find_related",
            "label": label_by_action["tier2_find_related"],
            "status": s2_status,
            "summary": s2_summary,
            "detail": s2_detail,
        }
    )

    if related_count > 0 and case_id is not None:
        s3_status = "executed"
        verb = "created" if created else ("extended" if extended else "updated")
        s3_summary = f"Result: Case `{case_id}` {verb} — {len(related_ids)} alert(s) linked"
    elif case_id is not None and related_count == 0:
        s3_status = "skipped"
        s3_summary = f"Result: no new aggregation — existing Case `{case_id}` (no siblings)"
    else:
        s3_status = "skipped"
        s3_summary = "Result: Case not created — no related alerts to aggregate"
    s3_detail = json.dumps(
        {
            "case_id": str(case_id) if case_id else None,
            "created": created,
            "extended": extended,
            "alert_ids": [str(x) for x in related_ids],
        }
    )
    await _emit_tier2_step(
        db,
        tenant_id=tenant_id,
        alert_id=alert_id,
        run_token=run_token,
        action_name="tier2_aggregate_case",
        summary=s3_summary,
        status=s3_status,
        detail=s3_detail,
        output_payload={
            "case_id": str(case_id) if case_id else None,
            "created": created,
            "extended": extended,
        },
    )
    steps_out.append(
        {
            "action_name": "tier2_aggregate_case",
            "label": label_by_action["tier2_aggregate_case"],
            "status": s3_status,
            "summary": s3_summary,
            "detail": s3_detail,
        }
    )

    if investigate_queued and case_id is not None and related_count > 0:
        s4_status = "recorded"
        s4_summary = (
            f"Result: Investigate queued on Case `{case_id}` "
            f"with {len(related_ids)} linked alert(s)"
        )
    elif investigate_queued:
        s4_status = "recorded"
        s4_summary = "Result: Investigate will run on this alert alone (no siblings)"
    else:
        s4_status = "skipped"
        s4_summary = (
            "Result: Investigate not started yet — use Overview → Start AI Investigation"
        )
    await _emit_tier2_step(
        db,
        tenant_id=tenant_id,
        alert_id=alert_id,
        run_token=run_token,
        action_name="tier2_investigate",
        summary=s4_summary,
        status=s4_status,
        output_payload={
            "case_id": str(case_id) if case_id else None,
            "investigate_queued": investigate_queued,
        },
    )
    steps_out.append(
        {
            "action_name": "tier2_investigate",
            "label": label_by_action["tier2_investigate"],
            "status": s4_status,
            "summary": s4_summary,
            "detail": None,
        }
    )

    if case_id is not None and related_count > 0:
        s5_status = "recorded"
        s5_summary = (
            f"Result: Case report includes {len(related_ids)} related alert(s) "
            f"(GET /cases/{case_id}/report.md)"
        )
    elif case_id is not None:
        s5_status = "skipped"
        s5_summary = f"Result: Case report covers only this alert (Case `{case_id}`)"
    else:
        s5_status = "skipped"
        s5_summary = "Result: multi-alert Case report not ready — Case was not created"
    await _emit_tier2_step(
        db,
        tenant_id=tenant_id,
        alert_id=alert_id,
        run_token=run_token,
        action_name="tier2_case_report",
        summary=s5_summary,
        status=s5_status,
        output_payload={
            "case_id": str(case_id) if case_id else None,
            "linked_alert_count": len(related_ids),
        },
    )
    steps_out.append(
        {
            "action_name": "tier2_case_report",
            "label": label_by_action["tier2_case_report"],
            "status": s5_status,
            "summary": s5_summary,
            "detail": None,
        }
    )

    await persist_tier2_snapshot(
        db,
        tenant_id=tenant_id,
        alert_id=alert_id,
        steps=steps_out,
        pivot={
            "src_ips": ips.src_ips,
            "dest_ips": ips.dest_ips,
            "related_alert_ids": [str(x) for x in related_ids],
            "case_id": str(case_id) if case_id else None,
            "run_token": run_token,
        },
    )
    return steps_out


async def run_tier2_investigate_preflight(
    db: AsyncSession,
    *,
    alert: Any,
    tenant_id: uuid.UUID,
    hours: int = _DEFAULT_HOURS,
    investigate_queued: bool = True,
) -> tuple[Tier2PivotResult, list[dict[str, Any]]]:
    """Full Tier-2 preflight used by Investigate and Runbook Tier-2 button.

    When ``AISOC_TIER2_ADAPTIVE`` is enabled, delegates to the adaptive engine
    (never IP-gated). Shadow mode runs adaptive for enrichment without Case
    mutations, then continues the legacy path.
    """
    from app.services.tier2_adaptive.feature_flags import (
        selected_tier2_path,
        tier2_adaptive_enabled,
        tier2_adaptive_shadow,
    )

    path = selected_tier2_path()
    logger.info("tier2.preflight.path", path=path)

    if tier2_adaptive_enabled():
        from app.services.tier2_adaptive.engine import run_adaptive_investigate_preflight

        adaptive, summaries = await run_adaptive_investigate_preflight(
            db,
            alert=alert,
            tenant_id=tenant_id,
            hours=hours,
            investigate_queued=investigate_queued,
            shadow=False,
        )
        # Adapt to legacy return shape for API compatibility.
        return (
            Tier2PivotResult(
                src_ips=adaptive.entities.values("ip")[:8],
                dest_ips=adaptive.entities.values("ip")[:8],
                related_alert_ids=adaptive.related_alert_ids,
                case_id=adaptive.case_id,
                case_created=adaptive.case_created,
                case_extended=adaptive.case_extended,
                window_hours=adaptive.window_hours,
                notes=adaptive.notes,
            ),
            summaries,
        )

    if tier2_adaptive_shadow():
        # Evaluate adaptive without Case writes; legacy path remains authoritative.
        try:
            from app.services.tier2_adaptive.engine import run_adaptive_pipeline_sync

            shadow_result = run_adaptive_pipeline_sync(
                alert, hours=hours, shadow=True
            )
            logger.info(
                "tier2.adaptive.shadow",
                profiles=shadow_result.profiles.names,
                case_action=shadow_result.case_decision.action,
                entities=len(shadow_result.entities.entities),
            )
        except Exception as exc:  # noqa: BLE001 — shadow must never break legacy
            logger.warning("tier2.adaptive.shadow_failed", error_type=type(exc).__name__)

    alert_id = alert.id if hasattr(alert, "id") else uuid.UUID(str(alert["id"]))
    run_token = uuid.uuid4().hex[:12]
    ips = extract_alert_ips(alert)
    notes: list[str] = []
    related_ids: list[uuid.UUID] = [alert_id]
    summaries: list[dict[str, Any]] = []
    case_id: uuid.UUID | None = None
    created = False
    extended = False
    existing_case = getattr(alert, "case_id", None)
    if isinstance(existing_case, uuid.UUID):
        case_id = existing_case

    if not ips.all_ips:
        notes.append("No src_ip/dest_ip resolved from llm_payload, raw_event, or affected_ips.")
        try:
            await emit_tier2_runbook_steps(
                db,
                tenant_id=tenant_id,
                alert_id=alert_id,
                run_token=run_token,
                ips=ips,
                related_ids=related_ids,
                related_summaries=[],
                case_id=case_id,
                created=False,
                extended=False,
                hours=hours,
                investigate_queued=investigate_queued,
            )
            await db.commit()
        except Exception as exc:  # noqa: BLE001
            await db.rollback()
            logger.warning("tier2.runbook_emit_failed", error_type=type(exc).__name__)
        return (
            Tier2PivotResult(
                src_ips=[],
                dest_ips=[],
                related_alert_ids=[str(alert_id)],
                case_id=str(case_id) if case_id else None,
                case_created=False,
                case_extended=False,
                window_hours=hours,
                notes=notes,
            ),
            [],
        )

    await backfill_affected_ips(db, alert_id=alert_id, tenant_id=tenant_id, ips=ips)
    related_ids = await find_related_alert_ids(
        db,
        tenant_id=tenant_id,
        seed_id=alert_id,
        ips=ips,
        hours=hours,
    )
    summaries = await _load_related_summaries(db, tenant_id=tenant_id, alert_ids=related_ids)

    if len(related_ids) > 1:
        case_id, created, extended = await aggregate_into_case(
            db,
            tenant_id=tenant_id,
            seed=alert,
            alert_ids=related_ids,
            ips=ips,
        )
        notes.append(
            f"Tier-2 pivot: {len(related_ids)} alert(s) on "
            f"dest={ips.dest_ips or '-'} src={ips.src_ips or '-'} → case {case_id}"
        )
    else:
        notes.append(
            f"Tier-2 IP check complete — no related alerts in {hours}h "
            f"(src={ips.src_ips or '—'}, dest={ips.dest_ips or '—'})."
        )

    await db.commit()
    try:
        if created and case_id is not None:
            from app.services.runbook.emitters import emit_case_created

            await emit_case_created(
                db,
                tenant_id=tenant_id,
                case_id=case_id,
                case_title=f"Tier-2 IP pivot ({len(related_ids)} alerts)",
                alert_ids=[str(x) for x in related_ids],
                actor_label="tier2-investigate",
                severity=str(getattr(alert, "severity", "") or None),
                disposition=str(getattr(alert, "disposition", "") or None),
                idempotency_key=f"tier2-case-created:{case_id}:{run_token}",
            )
        await emit_tier2_runbook_steps(
            db,
            tenant_id=tenant_id,
            alert_id=alert_id,
            run_token=run_token,
            ips=ips,
            related_ids=related_ids,
            related_summaries=summaries,
            case_id=case_id,
            created=created,
            extended=extended,
            hours=hours,
            investigate_queued=investigate_queued,
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — pivot must not fail Investigate
        await db.rollback()
        logger.warning("tier2.runbook_emit_failed", error_type=type(exc).__name__)

    result = Tier2PivotResult(
        src_ips=ips.src_ips,
        dest_ips=ips.dest_ips,
        related_alert_ids=[str(x) for x in related_ids],
        case_id=str(case_id) if case_id else None,
        case_created=created,
        case_extended=extended,
        window_hours=hours,
        notes=notes,
    )
    logger.info(
        "tier2.ip_pivot.done",
        alert_id=str(alert_id),
        related=len(related_ids),
        case_id=str(case_id) if case_id else None,
        created=created,
        extended=extended,
        run_token=run_token,
    )
    return result, summaries


def tier2_step_catalog() -> list[dict[str, str]]:
    """Static catalog for the Runbook UI before any run has executed."""
    try:
        from app.services.tier2_adaptive.feature_flags import tier2_adaptive_enabled
        from app.services.tier2_adaptive.engine import adaptive_step_catalog

        if tier2_adaptive_enabled():
            return adaptive_step_catalog()
    except Exception:  # noqa: BLE001 — catalog must never raise
        pass
    return [dict(item) for item in TIER2_RUNBOOK_STEPS]
