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
    case_title = campaign_case_title(theme, entities)
    if ips.dest_ips:
        case_title = f"Tier-2 dest_ip pivot · {', '.join(ips.dest_ips[:2])}"[:500]
    elif ips.src_ips:
        case_title = f"Tier-2 src_ip pivot · {', '.join(ips.src_ips[:2])}"[:500]
    tags = campaign_tags(theme=theme, campaign_key=camp_key, source="tier2-investigate")
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


async def run_tier2_investigate_preflight(
    db: AsyncSession,
    *,
    alert: Any,
    tenant_id: uuid.UUID,
    hours: int = _DEFAULT_HOURS,
) -> tuple[Tier2PivotResult, list[dict[str, Any]]]:
    """Full Tier-2 preflight used by ``POST /agents/investigate``."""
    alert_id = alert.id if hasattr(alert, "id") else uuid.UUID(str(alert["id"]))
    ips = extract_alert_ips(alert)
    notes: list[str] = []
    if not ips.all_ips:
        notes.append("No src_ip/dest_ip resolved from llm_payload, raw_event, or affected_ips.")
        return (
            Tier2PivotResult(
                src_ips=[],
                dest_ips=[],
                related_alert_ids=[str(alert_id)],
                case_id=str(alert.case_id) if getattr(alert, "case_id", None) else None,
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
    case_id: uuid.UUID | None = None
    created = False
    extended = False
    existing_case = getattr(alert, "case_id", None)
    if isinstance(existing_case, uuid.UUID):
        case_id = existing_case
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
        await db.commit()
        try:
            from app.services.runbook.emitters import emit_case_created
            from app.services.runbook.recorder import record_event

            if created:
                await emit_case_created(
                    db,
                    tenant_id=tenant_id,
                    case_id=case_id,
                    case_title=f"Tier-2 IP pivot ({len(related_ids)} alerts)",
                    alert_ids=[str(x) for x in related_ids],
                    actor_label="tier2-investigate",
                    severity=str(getattr(alert, "severity", "") or None),
                    disposition=str(getattr(alert, "disposition", "") or None),
                    idempotency_key=f"tier2-case-created:{case_id}",
                )
            await record_event(
                db,
                tenant_id=tenant_id,
                subject_type="alert",
                subject_id=alert_id,
                stage="investigate",
                kind="enrichment",
                summary=(
                    f"Tier-2 IP check · src={','.join(ips.src_ips) or '—'} · "
                    f"dest={','.join(ips.dest_ips) or '—'} · "
                    f"{max(0, len(related_ids) - 1)} related in {hours}h"
                ),
                detail=json.dumps(
                    {
                        "src_ips": ips.src_ips,
                        "dest_ips": ips.dest_ips,
                        "related_alert_ids": [str(x) for x in related_ids],
                        "case_id": str(case_id) if case_id else None,
                    },
                    ensure_ascii=False,
                )[:4000],
                status="recorded",
                actor_type="system",
                actor_label="tier2-investigate",
                action_name="ip_pivot_aggregate",
                output_payload={
                    "related_count": max(0, len(related_ids) - 1),
                    "case_id": str(case_id) if case_id else None,
                },
                idempotency_key=f"tier2-ip-pivot:{alert_id}:{hours}",
            )
            await db.commit()
        except Exception as exc:  # noqa: BLE001 — pivot must not fail Investigate
            await db.rollback()
            logger.warning("tier2.runbook_emit_failed", error_type=type(exc).__name__)
    else:
        notes.append(
            f"Tier-2 IP check complete — no related alerts in {hours}h "
            f"(src={ips.src_ips or '—'}, dest={ips.dest_ips or '—'})."
        )
        await db.commit()
        try:
            from app.services.runbook.recorder import record_event

            await record_event(
                db,
                tenant_id=tenant_id,
                subject_type="alert",
                subject_id=alert_id,
                stage="investigate",
                kind="enrichment",
                summary=(
                    f"Tier-2 IP check · src={','.join(ips.src_ips) or '—'} · "
                    f"dest={','.join(ips.dest_ips) or '—'} · 0 related in {hours}h"
                ),
                status="recorded",
                actor_type="system",
                actor_label="tier2-investigate",
                action_name="ip_pivot_check",
                output_payload={"related_count": 0, "src_ips": ips.src_ips, "dest_ips": ips.dest_ips},
                idempotency_key=f"tier2-ip-pivot:{alert_id}:{hours}",
            )
            await db.commit()
        except Exception as exc:  # noqa: BLE001
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
    )
    return result, summaries
