"""Purge display-identical duplicate alerts and cases within a tenant.

Analyst-facing surfaces (SOC Funnel + Alerts) show many ESCU rows that look
identical even when ``dedup_hash`` / ``source_event_ids`` differ. This module
collapses those by **display fingerprint** (title, severity, rule, entities,
disposition), keeps one canonical row, re-points case links, then DELETEs the
rest.

Cases from the agentic funnel that share title+severity are likewise merged.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_AGENTIC_CREATORS = ("agentic-funnel", "agentic-funnel-backfill")
_PRIMARY_ALERT_RE = re.compile(
    r"Primary alert:\s*[0-9a-fA-F-]{36}",
    re.IGNORECASE,
)
_LINKED_COUNT_RE = re.compile(r"Linked alerts:\s*\d+", re.IGNORECASE)
_CONF_RE = re.compile(r"confidence=\d+(?:\.\d+)?", re.IGNORECASE)
_DELETE_CHUNK = 400


def normalize_case_description(description: str | None, *, created_by: str | None) -> str:
    """Strip per-run noise so identical agentic cases share one fingerprint."""
    body = (description or "").strip()
    creator = (created_by or "").strip().lower()
    if creator in _AGENTIC_CREATORS or creator.startswith("agentic-funnel"):
        body = _PRIMARY_ALERT_RE.sub("Primary alert: <id>", body)
        body = _LINKED_COUNT_RE.sub("Linked alerts: N", body)
        body = _CONF_RE.sub("confidence=<n>", body)
        body = re.sub(r"\s+", " ", body).strip()
    return body


def case_content_key(
    *,
    title: str,
    severity: str,
    description: str | None,
    created_by: str | None,
) -> str:
    """Stable grouping key for exact/near-exact case duplicates."""
    creator = (created_by or "").strip().lower()
    if creator in _AGENTIC_CREATORS or creator.startswith("agentic-funnel"):
        return f"agentic|{title.strip().lower()}|{severity.strip().lower()}"
    norm = normalize_case_description(description, created_by=created_by)
    return f"manual|{title.strip().lower()}|{severity.strip().lower()}|{norm}"


def alert_display_key(row: dict[str, Any]) -> str:
    """Fingerprint of what analysts see as 'the same alert'.

    Ignores ``dedup_hash`` and ``source_event_ids`` — Splunk ESCU often mints a
    new event id per poll while title/rule/entities stay identical.
    """
    title = (row.get("title") or "").strip().lower()
    severity = (row.get("severity") or "").strip().lower()
    rule = (
        (row.get("rule_id") or row.get("rule_name") or "").strip().lower()
    )
    disposition = (row.get("disposition") or "").strip().lower()
    hosts = _json_stable(row.get("affected_hosts"))
    ips = _json_stable(row.get("affected_ips"))
    users = _json_stable(row.get("affected_users"))
    # When entities are empty, title+severity+rule still collapses ESCU floods.
    return f"display|{title}|{severity}|{rule}|{disposition}|{hosts}|{ips}|{users}"


def pick_canonical_case(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Prefer most linked alerts, then external activity, then oldest."""

    def sort_key(row: dict[str, Any]) -> tuple:
        alert_n = len(row.get("alert_ids") or [])
        has_ref = 1 if row.get("has_external_ref") else 0
        opened = row.get("opened_at")
        return (-alert_n, -has_ref, opened or 0)

    return sorted(rows, key=sort_key)[0]


def pick_canonical_alert(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Prefer cased / further-along funnel stage, then oldest created_at."""
    stage_rank = {
        "jira_pushed": 6,
        "ready_for_jira": 5,
        "cased": 4,
        "investigating": 3,
        "triaged": 2,
        "ingested": 1,
        "suppressed": 0,
    }

    def sort_key(row: dict[str, Any]) -> tuple:
        has_case = 1 if row.get("case_id") else 0
        stage = stage_rank.get(str(row.get("funnel_stage") or "ingested"), 1)
        created = row.get("created_at")
        return (-has_case, -stage, created or 0)

    return sorted(rows, key=sort_key)[0]


def _json_stable(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        parts = sorted({str(v).strip().lower() for v in value if str(v).strip()})
        return "|".join(parts)
    if isinstance(value, dict):
        return str(sorted((str(k).lower(), str(v).lower()) for k, v in value.items()))
    return str(value).strip().lower()


async def _delete_alert_ids(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    loser_ids: list[uuid.UUID],
) -> None:
    if not loser_ids:
        return
    for i in range(0, len(loser_ids), _DELETE_CHUNK):
        chunk = loser_ids[i : i + _DELETE_CHUNK]
        ids = [str(x) for x in chunk]
        await db.execute(
            text(
                """
                UPDATE aisoc_cases
                   SET alert_ids = ARRAY(
                         SELECT x FROM unnest(alert_ids) AS t(x)
                          WHERE NOT (x = ANY(CAST(:ids AS uuid[])))
                       ),
                       updated_at = now()
                 WHERE tenant_id = :tid
                   AND alert_ids && CAST(:ids AS uuid[])
                """
            ).bindparams(tid=tenant_id, ids=ids)
        )
        await db.execute(
            text(
                """
                DELETE FROM alerts
                 WHERE tenant_id = :tid AND id = ANY(CAST(:ids AS uuid[]))
                """
            ).bindparams(tid=tenant_id, ids=ids)
        )


async def dedupe_exact_alerts(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Delete display-identical duplicate alert rows; keep one per group."""
    rows = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, disposition, case_id, dedup_hash,
                       rule_id, rule_name, source_event_ids, affected_hosts,
                       affected_ips, affected_users, ai_summary, funnel_stage,
                       created_at
                  FROM alerts
                 WHERE tenant_id = :tid
                """
            ).bindparams(tid=tenant_id)
        )
    ).mappings().all()

    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        r = dict(row)
        # Always use display key so distinct Splunk event ids still collapse.
        # Also union same dedup_hash into that group via secondary index.
        key = alert_display_key(r)
        groups.setdefault(key, []).append(r)

    # Second pass: if two groups share a dedup_hash member, merge them
    # (defensive — rare when display keys already match).
    hash_to_key: dict[str, str] = {}
    merge_into: dict[str, str] = {}
    for key, members in groups.items():
        for m in members:
            h = m.get("dedup_hash")
            if not h:
                continue
            hs = str(h)
            if hs in hash_to_key and hash_to_key[hs] != key:
                merge_into[key] = hash_to_key[hs]
            else:
                hash_to_key[hs] = key
    if merge_into:
        for src, dst in list(merge_into.items()):
            while dst in merge_into:
                dst = merge_into[dst]
            if src == dst or src not in groups:
                continue
            groups.setdefault(dst, []).extend(groups.pop(src))

    deleted: list[str] = []
    kept: list[str] = []
    all_losers: list[uuid.UUID] = []
    for members in groups.values():
        # Deduplicate member ids if merge created overlaps
        by_id: dict[str, dict[str, Any]] = {str(m["id"]): m for m in members}
        unique = list(by_id.values())
        if len(unique) < 2:
            continue
        canonical = pick_canonical_alert(unique)
        kept.append(str(canonical["id"]))
        losers = [m for m in unique if m["id"] != canonical["id"]]
        loser_ids = [m["id"] for m in losers]
        deleted.extend(str(x) for x in loser_ids)
        if dry_run:
            continue
        if not canonical.get("case_id"):
            for m in losers:
                if m.get("case_id"):
                    await db.execute(
                        text(
                            """
                            UPDATE alerts SET case_id = :cid, updated_at = now()
                             WHERE id = :id AND tenant_id = :tid
                            """
                        ).bindparams(cid=m["case_id"], id=canonical["id"], tid=tenant_id)
                    )
                    break
        all_losers.extend(loser_ids)

    if not dry_run and all_losers:
        await _delete_alert_ids(db, tenant_id=tenant_id, loser_ids=all_losers)

    return {
        "groups_collapsed": sum(
            1
            for m in groups.values()
            if len({str(x["id"]) for x in m}) >= 2
        ),
        "alerts_deleted": len(deleted),
        "alerts_kept": len(kept),
        "deleted_ids": deleted[:50],
        "dry_run": dry_run,
    }


async def dedupe_exact_cases(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Merge/delete exact-duplicate cases; keep one per content group."""
    has_refs = (
        await db.execute(text("SELECT to_regclass('public.case_external_refs') IS NOT NULL"))
    ).scalar()

    if has_refs:
        rows = (
            await db.execute(
                text(
                    """
                    SELECT c.id, c.title, c.description, c.severity, c.status,
                           c.alert_ids, c.created_by, c.opened_at,
                           EXISTS(
                             SELECT 1 FROM case_external_refs r WHERE r.case_id = c.id
                           ) AS has_external_ref
                      FROM aisoc_cases c
                     WHERE c.tenant_id = :tid
                    """
                ).bindparams(tid=tenant_id)
            )
        ).mappings().all()
    else:
        rows = (
            await db.execute(
                text(
                    """
                    SELECT id, title, description, severity, status,
                           alert_ids, created_by, opened_at,
                           false AS has_external_ref
                      FROM aisoc_cases
                     WHERE tenant_id = :tid
                    """
                ).bindparams(tid=tenant_id)
            )
        ).mappings().all()

    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        r = dict(row)
        key = case_content_key(
            title=str(r.get("title") or ""),
            severity=str(r.get("severity") or "medium"),
            description=r.get("description"),
            created_by=r.get("created_by"),
        )
        groups.setdefault(key, []).append(r)

    deleted: list[str] = []
    kept: list[str] = []
    alerts_relinked = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        canonical = pick_canonical_case(members)
        kept.append(str(canonical["id"]))
        losers = [m for m in members if m["id"] != canonical["id"]]
        if dry_run:
            deleted.extend(str(m["id"]) for m in losers)
            continue

        merged_alerts: list[uuid.UUID] = list(canonical.get("alert_ids") or [])
        seen = {str(a) for a in merged_alerts}
        for loser in losers:
            for aid in loser.get("alert_ids") or []:
                sid = str(aid)
                if sid not in seen:
                    seen.add(sid)
                    merged_alerts.append(aid if isinstance(aid, uuid.UUID) else uuid.UUID(sid))
            await db.execute(
                text(
                    """
                    UPDATE alerts
                       SET case_id = :cid, updated_at = now()
                     WHERE tenant_id = :tid AND case_id = :old
                    """
                ).bindparams(cid=canonical["id"], tid=tenant_id, old=loser["id"])
            )
            alerts_relinked += 1
            if has_refs:
                await db.execute(
                    text("DELETE FROM case_external_refs WHERE case_id = :cid").bindparams(
                        cid=loser["id"]
                    )
                )
            await db.execute(
                text("DELETE FROM aisoc_cases WHERE id = :cid AND tenant_id = :tid").bindparams(
                    cid=loser["id"], tid=tenant_id
                )
            )
            deleted.append(str(loser["id"]))

        await db.execute(
            text(
                """
                UPDATE aisoc_cases
                   SET alert_ids = CAST(:aids AS uuid[]),
                       updated_at = now()
                 WHERE id = :cid AND tenant_id = :tid
                """
            ).bindparams(
                aids=[str(a) for a in merged_alerts],
                cid=canonical["id"],
                tid=tenant_id,
            )
        )

    return {
        "groups_collapsed": sum(1 for m in groups.values() if len(m) >= 2),
        "cases_deleted": len(deleted),
        "cases_kept": len(kept),
        "alerts_relinked_batches": alerts_relinked,
        "deleted_ids": deleted[:50],
        "dry_run": dry_run,
    }


async def dedupe_exact(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run case then alert display-dedupe (cases first so alert_ids stay coherent)."""
    cases = await dedupe_exact_cases(db, tenant_id=tenant_id, dry_run=dry_run)
    alerts = await dedupe_exact_alerts(db, tenant_id=tenant_id, dry_run=dry_run)
    if not dry_run:
        await db.commit()
    return {"cases": cases, "alerts": alerts}
