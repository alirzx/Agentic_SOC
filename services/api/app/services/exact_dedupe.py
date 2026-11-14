"""Collapse repeated logical alerts and cases within a tenant.

Layer-2 (``AISOC_ALERT_DEDUP_V2``, default on): entity-aware
``alert_logical_key`` — excludes severity/disposition; different hosts/users
stay separate; configurable time window (default 15m). Occurrences are
preserved (``canonical_alert_id``, ``alert_occurrences`` when available).

Legacy display fingerprint (``alert_display_key``) remains for shadow mode and
when V2 is disabled.

Cases from the agentic funnel that share title+severity are still hard-merged.
"""

from __future__ import annotations

import json
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
_DEFAULT_WINDOW_SECONDS = 900


def _dedup_flags() -> tuple[bool, bool, int]:
    """Return (v2_enabled, shadow, window_seconds)."""
    try:
        from app.core.config import get_settings

        settings = get_settings()
        v2 = bool(getattr(settings, "AISOC_ALERT_DEDUP_V2", True))
        shadow = bool(getattr(settings, "AISOC_DEDUP_SHADOW", False))
        window = int(
            getattr(settings, "AISOC_ALERT_DEDUP_WINDOW_SECONDS", _DEFAULT_WINDOW_SECONDS)
            or _DEFAULT_WINDOW_SECONDS
        )
        return v2, shadow, max(1, window)
    except Exception:  # noqa: BLE001 — tests without settings
        return True, False, _DEFAULT_WINDOW_SECONDS


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

    Ignores ``dedup_hash``, ``source_event_ids``, and per-row entity lists —
    Splunk ESCU re-fires the same rule across hosts / polls while title + rule
    stay identical. Entities are unioned onto the canonical survivor instead
    of keeping the key apart (see ``merge_alert_entities``).
    """
    title = (row.get("title") or "").strip().lower()
    severity = (row.get("severity") or "").strip().lower()
    rule = (
        (row.get("rule_id") or row.get("rule_name") or "").strip().lower()
    )
    disposition = (row.get("disposition") or "").strip().lower()
    return f"display|{title}|{severity}|{rule}|{disposition}"


def merge_alert_entities(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Union hosts / ips / users across a duplicate group (preserve first-seen casing)."""

    def collect(field: str) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for row in rows:
            raw = row.get(field)
            values: list[Any]
            if raw is None:
                values = []
            elif isinstance(raw, list):
                values = raw
            else:
                values = [raw]
            for value in values:
                text_value = str(value).strip()
                if not text_value:
                    continue
                key = text_value.lower()
                if key in seen:
                    continue
                seen.add(key)
                out.append(text_value)
        return out

    return {
        "affected_hosts": collect("affected_hosts"),
        "affected_ips": collect("affected_ips"),
        "affected_users": collect("affected_users"),
    }


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
        "deduplicated": -1,
    }

    def sort_key(row: dict[str, Any]) -> tuple:
        has_case = 1 if row.get("case_id") else 0
        stage = stage_rank.get(str(row.get("funnel_stage") or "ingested"), 1)
        created = row.get("created_at")
        return (-has_case, -stage, created or 0)

    return sorted(rows, key=sort_key)[0]


async def _mark_alerts_deduplicated(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    loser_ids: list[uuid.UUID],
    canonical_id: uuid.UUID,
    preserve_case_membership: bool = True,
    logical_key: str | None = None,
) -> None:
    """Soft-collapse losers into the Deduplicated funnel column (keep the row).

    V2 preserves case membership so Case/Tier-2 aggregation does not lose
    alerts. Legacy mode may still clear ``case_id`` when
    ``preserve_case_membership=False``.
    """
    if not loser_ids:
        return
    for i in range(0, len(loser_ids), _DELETE_CHUNK):
        chunk = loser_ids[i : i + _DELETE_CHUNK]
        ids = [str(x) for x in chunk]
        if not preserve_case_membership:
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
        case_clause = "" if preserve_case_membership else "case_id = NULL,"
        await db.execute(
            text(
                f"""
                UPDATE alerts
                   SET funnel_stage = 'deduplicated',
                       {case_clause}
                       tags = COALESCE(tags, '[]'::jsonb) || CAST(:extra AS jsonb),
                       updated_at = now()
                 WHERE tenant_id = :tid
                   AND id = ANY(CAST(:ids AS uuid[]))
                   AND funnel_stage IS DISTINCT FROM 'deduplicated'
                """
            ).bindparams(
                tid=tenant_id,
                ids=ids,
                extra=json.dumps(
                    [
                        "deduplicated",
                        f"deduplicated_into:{canonical_id}",
                        "occurrence_of_logical_alert",
                    ]
                ),
            )
        )
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET occurrence_count = COALESCE(occurrence_count, 1) + :n,
                       updated_at = now()
                 WHERE tenant_id = :tid AND id = :cid
                """
            ).bindparams(tid=tenant_id, cid=canonical_id, n=len(chunk))
        )
        # Migration 074 columns — best-effort.
        try:
            await db.execute(
                text(
                    """
                    UPDATE alerts
                       SET canonical_alert_id = :cid,
                           alert_dedup_key = COALESCE(:lkey, alert_dedup_key),
                           updated_at = now()
                     WHERE tenant_id = :tid
                       AND id = ANY(CAST(:ids AS uuid[]))
                    """
                ).bindparams(
                    tid=tenant_id, ids=ids, cid=canonical_id, lkey=logical_key
                )
            )
            await db.execute(
                text(
                    """
                    UPDATE alerts
                       SET alert_dedup_key = COALESCE(:lkey, alert_dedup_key),
                           updated_at = now()
                     WHERE tenant_id = :tid AND id = :cid
                    """
                ).bindparams(tid=tenant_id, cid=canonical_id, lkey=logical_key)
            )
        except Exception:  # noqa: BLE001
            pass
        # Best-effort occurrence rows (table may be absent pre-migration 074).
        try:
            for loser_id in chunk:
                await db.execute(
                    text(
                        """
                        INSERT INTO alert_occurrences (
                            id, tenant_id, alert_id, source_alert_id,
                            source_event_ids, seen_at, occurrence_meta
                        )
                        SELECT
                            :oid,
                            :tid,
                            :cid,
                            :sid,
                            COALESCE(a.source_event_ids, '[]'::jsonb),
                            COALESCE(a.event_time, a.created_at, now()),
                            CAST(:meta AS jsonb)
                          FROM alerts a
                         WHERE a.id = :sid AND a.tenant_id = :tid
                        """
                    ).bindparams(
                        oid=uuid.uuid4(),
                        tid=tenant_id,
                        cid=canonical_id,
                        sid=loser_id,
                        meta=json.dumps(
                            {
                                "layer": "alert_dedup_v2",
                                "logical_key": logical_key,
                            }
                        ),
                    )
                )
        except Exception:  # noqa: BLE001 — pre-074 schema
            pass


def _group_alerts_for_dedupe(
    rows: list[dict[str, Any]],
    *,
    v2: bool,
    window_seconds: int,
) -> dict[str, list[dict[str, Any]]]:
    """Build collapse groups: V2 logical key + time window, or legacy display key."""
    from app.services.dedup.alert_identity import (
        alert_logical_key,
        within_dedup_window,
    )

    groups: dict[str, list[dict[str, Any]]] = {}
    if not v2:
        for r in rows:
            groups.setdefault(alert_display_key(r), []).append(r)
        return groups

    # V2: bucket by logical key, then only collapse members inside the window
    # of the canonical (oldest) row — out-of-window stays independent.
    by_key: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        r = dict(r)
        r["_logical_key"] = alert_logical_key({**r, "tenant_id": r.get("tenant_id")})
        by_key.setdefault(r["_logical_key"], []).append(r)

    for key, members in by_key.items():
        if len(members) < 2:
            groups[key] = members
            continue
        members_sorted = sorted(
            members,
            key=lambda m: m.get("created_at") or m.get("event_time") or 0,
        )
        # Greedy window clusters from earliest.
        clusters: list[list[dict[str, Any]]] = []
        for row in members_sorted:
            placed = False
            for cluster in clusters:
                if within_dedup_window(
                    cluster[0], row, window_seconds=window_seconds
                ):
                    cluster.append(row)
                    placed = True
                    break
            if not placed:
                clusters.append([row])
        for idx, cluster in enumerate(clusters):
            groups[f"{key}#w{idx}"] = cluster
    return groups


async def dedupe_exact_alerts(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Soft-collapse repeated logical alerts into the Deduplicated column.

    V2 (default): entity-aware key + time window; preserves case membership.
    Legacy: title|severity|rule|disposition display key.
    """
    v2, shadow, window_seconds = _dedup_flags()
    rows = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, disposition, case_id, dedup_hash,
                       rule_id, rule_name, source_event_ids, affected_hosts,
                       affected_ips, affected_users, ai_summary, funnel_stage,
                       created_at, event_time, connector_type, llm_payload,
                       raw_event, enrichment_data, iocs, mitre_tactics
                  FROM alerts
                 WHERE tenant_id = :tid
                   AND COALESCE(funnel_stage, 'ingested') <> 'deduplicated'
                """
            ).bindparams(tid=tenant_id)
        )
    ).mappings().all()

    row_dicts = [{**dict(r), "tenant_id": str(tenant_id)} for r in rows]
    shadow_report: dict[str, Any] | None = None
    if shadow:
        from app.services.dedup.shadow import compare_grouping

        shadow_report = compare_grouping(row_dicts, window_seconds=window_seconds)

    groups = _group_alerts_for_dedupe(
        row_dicts, v2=v2, window_seconds=window_seconds
    )

    # Same dedup_hash still merges (true Layer-1 twins) even across display keys.
    hash_to_key: dict[str, str] = {}
    merge_into: dict[str, str] = {}
    for key, members in groups.items():
        for m in members:
            h = m.get("dedup_hash")
            if not h or str(h).startswith("legacy_dup:"):
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

    collapsed: list[str] = []
    kept: list[str] = []
    for members in groups.values():
        by_id: dict[str, dict[str, Any]] = {str(m["id"]): m for m in members}
        unique = list(by_id.values())
        if len(unique) < 2:
            continue
        canonical = pick_canonical_alert(unique)
        kept.append(str(canonical["id"]))
        losers = [m for m in unique if m["id"] != canonical["id"]]
        loser_ids = [m["id"] for m in losers]
        collapsed.extend(str(x) for x in loser_ids)
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
                        ).bindparams(
                            cid=m["case_id"], id=canonical["id"], tid=tenant_id
                        )
                    )
                    break
        merged = merge_alert_entities(unique)
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET affected_hosts = CAST(:hosts AS jsonb),
                       affected_ips = CAST(:ips AS jsonb),
                       affected_users = CAST(:users AS jsonb),
                       updated_at = now()
                 WHERE tenant_id = :tid AND id = :cid
                """
            ).bindparams(
                tid=tenant_id,
                cid=canonical["id"],
                hosts=json.dumps(merged["affected_hosts"]),
                ips=json.dumps(merged["affected_ips"]),
                users=json.dumps(merged["affected_users"]),
            )
        )
        logical_key = canonical.get("_logical_key")
        if not logical_key and v2:
            from app.services.dedup.alert_identity import alert_logical_key

            logical_key = alert_logical_key(canonical)
        await _mark_alerts_deduplicated(
            db,
            tenant_id=tenant_id,
            loser_ids=loser_ids,
            canonical_id=canonical["id"],
            preserve_case_membership=v2,
            logical_key=logical_key if isinstance(logical_key, str) else None,
        )

    result: dict[str, Any] = {
        "groups_collapsed": sum(
            1 for m in groups.values() if len({str(x["id"]) for x in m}) >= 2
        ),
        "alerts_deleted": len(collapsed),
        "alerts_deduplicated": len(collapsed),
        "alerts_kept": len(kept),
        "deleted_ids": collapsed[:50],
        "dry_run": dry_run,
        "dedup_mode": "v2" if v2 else "legacy_display",
        "window_seconds": window_seconds if v2 else None,
    }
    if shadow_report is not None:
        result["shadow"] = shadow_report
    return result


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
