"""Purge exact-duplicate alerts and cases within a tenant.

Alert groups
------------
* Prefer ``dedup_hash`` (fusion fingerprint) when present.
* Otherwise hash stable content fields (title, severity, rule, entities,
  source_event_ids, disposition, ai_summary).

Case groups
-----------
* Agentic funnel / backfill cases: same ``title`` + ``severity`` (description
  only differs by primary-alert UUID / linked count).
* Other cases: exact ``title`` + ``severity`` + ``description``.

Keep one canonical row per group (richest, then oldest), re-point references,
then DELETE the losers.
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
        # Agentic rows share the same narrative template; title+severity is enough.
        return f"agentic|{title.strip().lower()}|{severity.strip().lower()}"
    norm = normalize_case_description(description, created_by=created_by)
    return f"manual|{title.strip().lower()}|{severity.strip().lower()}|{norm}"


def pick_canonical_case(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Prefer most linked alerts, then external activity, then oldest."""

    def sort_key(row: dict[str, Any]) -> tuple:
        alert_n = len(row.get("alert_ids") or [])
        has_ref = 1 if row.get("has_external_ref") else 0
        opened = row.get("opened_at")
        # richest first, then has ITSM, then oldest
        return (-alert_n, -has_ref, opened or 0)

    return sorted(rows, key=sort_key)[0]


def pick_canonical_alert(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Prefer cased alert, then oldest created_at."""

    def sort_key(row: dict[str, Any]) -> tuple:
        has_case = 1 if row.get("case_id") else 0
        created = row.get("created_at")
        return (-has_case, created or 0)

    return sorted(rows, key=sort_key)[0]


async def dedupe_exact_alerts(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Delete exact-duplicate alert rows; keep one per content group."""
    rows = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, disposition, case_id, dedup_hash,
                       rule_id, rule_name, source_event_ids, affected_hosts,
                       affected_ips, ai_summary, created_at
                  FROM alerts
                 WHERE tenant_id = :tid
                """
            ).bindparams(tid=tenant_id)
        )
    ).mappings().all()

    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        r = dict(row)
        if r.get("dedup_hash"):
            key = f"hash|{r['dedup_hash']}"
        else:
            key = (
                "content|"
                f"{(r.get('title') or '').strip().lower()}|"
                f"{(r.get('severity') or '').strip().lower()}|"
                f"{(r.get('rule_id') or '').strip().lower()}|"
                f"{(r.get('rule_name') or '').strip().lower()}|"
                f"{(r.get('disposition') or '').strip().lower()}|"
                f"{(r.get('ai_summary') or '').strip()}|"
                f"{_json_stable(r.get('source_event_ids'))}|"
                f"{_json_stable(r.get('affected_hosts'))}|"
                f"{_json_stable(r.get('affected_ips'))}"
            )
        groups.setdefault(key, []).append(r)

    deleted: list[str] = []
    kept: list[str] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        canonical = pick_canonical_alert(members)
        kept.append(str(canonical["id"]))
        losers = [m for m in members if m["id"] != canonical["id"]]
        loser_ids = [m["id"] for m in losers]
        if dry_run:
            deleted.extend(str(x) for x in loser_ids)
            continue
        # Prefer canonical case_id if losers were cased and canonical wasn't.
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
        for aid in loser_ids:
            await db.execute(
                text(
                    """
                    UPDATE aisoc_cases
                       SET alert_ids = array_remove(alert_ids, CAST(:aid AS uuid)),
                           updated_at = now()
                     WHERE tenant_id = :tid
                       AND CAST(:aid AS uuid) = ANY(alert_ids)
                    """
                ).bindparams(aid=str(aid), tid=tenant_id)
            )
        await db.execute(
            text(
                """
                DELETE FROM alerts
                 WHERE tenant_id = :tid AND id = ANY(CAST(:ids AS uuid[]))
                """
            ).bindparams(tid=tenant_id, ids=[str(x) for x in loser_ids])
        )
        deleted.extend(str(x) for x in loser_ids)

    return {
        "groups_collapsed": sum(1 for m in groups.values() if len(m) >= 2),
        "alerts_deleted": len(deleted),
        "alerts_kept": len(kept),
        "deleted_ids": deleted[:50],
        "dry_run": dry_run,
    }


def _json_stable(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "|".join(sorted(str(v) for v in value))
    return str(value)


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
                # Drop external refs on losers (canonical keeps its own).
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
    """Run case then alert exact-dedupe (cases first so alert_ids stay coherent)."""
    cases = await dedupe_exact_cases(db, tenant_id=tenant_id, dry_run=dry_run)
    alerts = await dedupe_exact_alerts(db, tenant_id=tenant_id, dry_run=dry_run)
    if not dry_run:
        await db.commit()
    return {"cases": cases, "alerts": alerts}
