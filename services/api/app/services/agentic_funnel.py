"""Agentic SOC funnel — backfill + reportable queue for existing alerts.

Turns a noisy 24h alert pile into:
* FP-tagged noise (low / info, or disposition already false_positive)
* Cases for true_positive / high-severity needs_review style alerts
* Linked siblings + investigation tasks with Splunk SPL checklists
* A reportable list (open cases tagged ``reportable``)
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()

_ATTACK_HINTS = re.compile(
    r"password\s*spray|brute\s*force|credential|lateral|ransomware|"
    r"c2|command\s*and\s*control|exfil|privilege\s*escalat|mimikatz|"
    r"lsass|kerberoast|dcsync|phishing|malware|exploit",
    re.I,
)
_NOISE_HINTS = re.compile(
    r"informational|policy\s*disabled|unapproved\s*port|heartbeat|"
    r"vulnerability\s*scan|inventory|config\s*change",
    re.I,
)


def _severity_rank(sev: str | None) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get((sev or "").lower(), 3)


def classify_backfill(alert: dict[str, Any]) -> str:
    """Heuristic disposition for alerts that never went through auto-triage."""
    existing = (alert.get("disposition") or "").strip().lower()
    if existing:
        return existing
    title = str(alert.get("title") or "")
    sev = str(alert.get("severity") or "medium").lower()
    if _ATTACK_HINTS.search(title) or sev in {"high", "critical"}:
        return "true_positive"
    if sev in {"low", "info"} and _NOISE_HINTS.search(title):
        return "false_positive"
    if sev == "medium" and _ATTACK_HINTS.search(title):
        return "true_positive"
    if sev in {"low", "info"}:
        return "false_positive"
    return "needs_review"


def _extract_entities(raw: dict[str, Any] | None) -> tuple[str | None, str | None, str | None]:
    raw = raw or {}
    host = None
    src = None
    dst = None
    device = raw.get("device") if isinstance(raw.get("device"), dict) else {}
    host = device.get("name") or raw.get("hostname")
    src_ep = raw.get("src_endpoint") if isinstance(raw.get("src_endpoint"), dict) else {}
    dst_ep = raw.get("dst_endpoint") if isinstance(raw.get("dst_endpoint"), dict) else {}
    src = src_ep.get("ip") or raw.get("src_ip")
    dst = dst_ep.get("ip") or raw.get("dst_ip")
    unmapped = raw.get("unmapped") if isinstance(raw.get("unmapped"), dict) else {}
    host = host or unmapped.get("host")
    return (
        str(host) if host else None,
        str(src) if src else None,
        str(dst) if dst else None,
    )


def _tasks_for(alert: dict[str, Any], host: str | None, src: str | None, dst: str | None) -> list[dict[str, str]]:
    title = str(alert.get("title") or "alert")
    tasks: list[dict[str, str]] = []
    if src and dst:
        tasks.append(
            {
                "title": f"Investigate traffic between {src} and {dst}",
                "description": (
                    f"Seen with «{title}». Correlate auth / network between these IPs in Splunk."
                ),
            }
        )
        tasks.append(
            {
                "title": f"SPL: {src} ↔ {dst}",
                "description": (
                    f'index=* (src="{src}" OR dest="{dst}" OR src_ip="{src}" OR dest_ip="{dst}") '
                    f"earliest=-24h | stats count by src, dest, user, sourcetype | sort -count"
                ),
            }
        )
    if host:
        tasks.append(
            {
                "title": f"Review host {host}",
                "description": f'index=* host="{host}" earliest=-24h | stats count by sourcetype, user',
            }
        )
    tasks.append(
        {
            "title": "Decide reportability",
            "description": f"Confirm whether «{title}» must be reported to stakeholders.",
        }
    )
    return tasks


def derive_funnel_stage(
    alert: dict[str, Any],
    *,
    has_external_ref: bool = False,
) -> str:
    """Best-effort stage for a legacy alert row (used by sync + tests).

    Priority (highest wins): jira_pushed → ready_for_jira → cased →
    suppressed → investigating → triaged → ingested.

    Ready for Jira uses the triage evidence bar (see ``passes_ready_for_jira_stage``).
    """
    from app.services.funnel_stages import passes_ready_for_jira_stage

    disposition = (alert.get("disposition") or "").strip().lower()
    tags = alert.get("tags")
    tag_fp = False
    if isinstance(tags, list):
        tag_fp = "false_positive" in {str(t).lower() for t in tags}
    elif isinstance(tags, dict):
        tag_fp = bool(tags.get("false_positive")) or "false_positive" in {
            str(t).lower() for t in (tags.get("labels") or [])
        }
    if disposition in {"false_positive", "benign", "benign_true_positive"} or tag_fp:
        if not alert.get("case_id"):
            return "suppressed"
    if alert.get("case_id"):
        if has_external_ref:
            return "jira_pushed"
        if passes_ready_for_jira_stage(
            disposition=disposition,
            severity=alert.get("severity"),
            confidence=alert.get("confidence") or alert.get("ai_score"),
            case_id=alert.get("case_id"),
            tags=tags,
            rule_id=alert.get("rule_id"),
            rule_name=alert.get("rule_name"),
            mitre_techniques=alert.get("mitre_techniques"),
            ai_summary=alert.get("ai_summary"),
            narrative=alert.get("narrative"),
        ):
            return "ready_for_jira"
        return "cased"
    if disposition in {"false_positive", "benign", "benign_true_positive"} or tag_fp:
        return "suppressed"
    status = (alert.get("status") or "").strip().lower()
    if status in {"investigating", "in_progress", "triaging"}:
        return "investigating"
    if disposition:
        return "triaged"
    return "ingested"


async def sync_legacy_funnel_stages(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    since: datetime,
) -> dict[str, int]:
    """Bulk-reconcile ``funnel_stage`` from disposition / case / ITSM / status.

    Safe to re-run: never downgrades ``jira_pushed``. Intended for alerts that
    pre-date the funnel_stage column (all stuck at ``ingested``).
    """
    counts: dict[str, int] = {
        "suppressed": 0,
        "jira_pushed": 0,
        "ready_for_jira": 0,
        "cased": 0,
        "investigating": 0,
        "triaged": 0,
    }

    def _n(result: Any) -> int:
        try:
            return int(result.rowcount or 0)
        except Exception:  # noqa: BLE001
            return 0

    counts["suppressed"] = _n(
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET funnel_stage = 'suppressed', updated_at = now()
                 WHERE tenant_id = :tid
                   AND created_at >= :since
                   AND case_id IS NULL
                   AND funnel_stage IS DISTINCT FROM 'suppressed'
                   AND (
                         disposition IN ('false_positive','benign','benign_true_positive')
                      OR tags @> '["false_positive"]'::jsonb
                   )
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    )
    has_external_refs = (
        await db.execute(text("SELECT to_regclass('public.case_external_refs') IS NOT NULL"))
    ).scalar()
    if has_external_refs:
        counts["jira_pushed"] = _n(
            await db.execute(
                text(
                    """
                    UPDATE alerts
                       SET funnel_stage = 'jira_pushed', updated_at = now()
                     WHERE tenant_id = :tid
                       AND created_at >= :since
                       AND case_id IS NOT NULL
                       AND funnel_stage IS DISTINCT FROM 'jira_pushed'
                       AND EXISTS (
                             SELECT 1 FROM case_external_refs r
                              WHERE r.case_id = alerts.case_id
                       )
                    """
                ).bindparams(tid=tenant_id, since=since)
            )
        )
    # Ready for Jira — triage evidence bar (NOT every TP+case):
    # high/critical OR investigation prose OR (medium + conf≥70 + rule/MITRE).
    counts["ready_for_jira"] = _n(
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET funnel_stage = 'ready_for_jira', updated_at = now()
                 WHERE tenant_id = :tid
                   AND created_at >= :since
                   AND case_id IS NOT NULL
                   AND disposition IN ('true_positive','escalate','likely_tp')
                   AND funnel_stage NOT IN ('jira_pushed','ready_for_jira')
                   AND (
                         lower(severity) IN ('high','critical')
                      OR length(COALESCE(ai_summary, '')) >= 80
                      OR length(COALESCE(narrative, '')) >= 80
                      OR (
                           lower(severity) = 'medium'
                       AND COALESCE(
                             confidence,
                             CASE
                               WHEN ai_score IS NULL THEN 0
                               WHEN ai_score <= 1 THEN CAST(ROUND(ai_score * 100) AS int)
                               ELSE CAST(ROUND(ai_score) AS int)
                             END
                           ) >= 70
                       AND (
                             NULLIF(rule_id, '') IS NOT NULL
                          OR NULLIF(rule_name, '') IS NOT NULL
                          OR jsonb_array_length(COALESCE(mitre_techniques, '[]'::jsonb)) > 0
                       )
                      )
                   )
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    )
    # Demote heuristic TP+case noise that was previously marked ready_for_jira.
    demoted = _n(
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET funnel_stage = 'cased', updated_at = now()
                 WHERE tenant_id = :tid
                   AND created_at >= :since
                   AND case_id IS NOT NULL
                   AND funnel_stage = 'ready_for_jira'
                   AND NOT (
                         lower(severity) IN ('high','critical')
                      OR length(COALESCE(ai_summary, '')) >= 80
                      OR length(COALESCE(narrative, '')) >= 80
                      OR (
                           lower(severity) = 'medium'
                       AND COALESCE(
                             confidence,
                             CASE
                               WHEN ai_score IS NULL THEN 0
                               WHEN ai_score <= 1 THEN CAST(ROUND(ai_score * 100) AS int)
                               ELSE CAST(ROUND(ai_score) AS int)
                             END
                           ) >= 70
                       AND (
                             NULLIF(rule_id, '') IS NOT NULL
                          OR NULLIF(rule_name, '') IS NOT NULL
                          OR jsonb_array_length(COALESCE(mitre_techniques, '[]'::jsonb)) > 0
                       )
                      )
                   )
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    )
    counts["cased"] = demoted + _n(
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET funnel_stage = 'cased', updated_at = now()
                 WHERE tenant_id = :tid
                   AND created_at >= :since
                   AND case_id IS NOT NULL
                   AND funnel_stage IN ('ingested','triaged','investigating','suppressed')
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    )
    counts["investigating"] = _n(
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET funnel_stage = 'investigating', updated_at = now()
                 WHERE tenant_id = :tid
                   AND created_at >= :since
                   AND funnel_stage = 'ingested'
                   AND case_id IS NULL
                   AND status IN ('investigating','in_progress','triaging')
                   AND COALESCE(disposition, '') NOT IN
                       ('false_positive','benign','benign_true_positive')
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    )
    counts["triaged"] = _n(
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET funnel_stage = 'triaged', updated_at = now()
                 WHERE tenant_id = :tid
                   AND created_at >= :since
                   AND funnel_stage = 'ingested'
                   AND case_id IS NULL
                   AND disposition IS NOT NULL
                   AND disposition NOT IN
                       ('false_positive','benign','benign_true_positive')
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    )
    return counts


async def run_backfill(db: AsyncSession, *, tenant_id: uuid.UUID, hours: int = 24) -> dict[str, Any]:
    """Classify + promote/tag alerts from the last ``hours`` for one tenant.

    Ends with a legacy ``funnel_stage`` sync so alerts created before the
    funnel column still land in Triaged / Suppressed / Cased / etc.
    """
    since = datetime.now(UTC) - timedelta(hours=max(1, min(hours, 168)))
    rows = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, status, disposition, case_id, tags,
                       affected_hosts, affected_ips, raw_event, created_at,
                       rule_id, rule_name, mitre_techniques, confidence, ai_score,
                       ai_summary, narrative
                  FROM alerts
                 WHERE tenant_id = :tid AND created_at >= :since
                 ORDER BY created_at DESC
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    ).mappings().all()

    fp_tagged = 0
    cases_created = 0
    linked = 0
    reportable: list[dict[str, Any]] = []
    skipped = 0

    for row in rows:
        alert = dict(row)
        alert_id = alert["id"]
        disposition = classify_backfill(alert)
        raw = alert.get("raw_event") if isinstance(alert.get("raw_event"), dict) else {}
        host, src, dst = _extract_entities(raw)
        hosts = alert.get("affected_hosts") if isinstance(alert.get("affected_hosts"), list) else []
        if not host and hosts:
            host = str(hosts[0])
        ips = alert.get("affected_ips") if isinstance(alert.get("affected_ips"), list) else []
        if not src and ips:
            src = str(ips[0])

        # Persist disposition if missing
        if not (alert.get("disposition") or "").strip():
            await db.execute(
                text(
                    """
                    UPDATE alerts
                       SET disposition = :d,
                           funnel_stage = CASE
                             WHEN :d IN ('false_positive','benign','benign_true_positive')
                             THEN 'suppressed' ELSE 'triaged' END,
                           status = CASE WHEN :d IN ('false_positive','benign','benign_true_positive')
                                         THEN 'resolved' ELSE status END,
                           resolved_at = CASE WHEN :d IN ('false_positive','benign','benign_true_positive')
                                              THEN now() ELSE resolved_at END,
                           updated_at = now()
                     WHERE id = :id AND tenant_id = :tid
                    """
                ).bindparams(d=disposition, id=alert_id, tid=tenant_id)
            )

        if disposition in {"false_positive", "benign", "benign_true_positive"}:
            await db.execute(
                text(
                    """
                    UPDATE alerts
                       SET tags = COALESCE(tags, '[]'::jsonb) || CAST(:tag AS JSONB),
                           disposition = COALESCE(NULLIF(disposition, ''), :d),
                           funnel_stage = 'suppressed',
                           status = 'resolved',
                           resolved_at = COALESCE(resolved_at, now()),
                           updated_at = now()
                     WHERE id = :id AND tenant_id = :tid
                    """
                ).bindparams(tag=json.dumps(["false_positive"]), d=disposition, id=alert_id, tid=tenant_id)
            )
            fp_tagged += 1
            continue

        if alert.get("case_id"):
            # Already cased — funnel_stage reconciled in sync_legacy_funnel_stages.
            skipped += 1
            continue

        if disposition not in {"true_positive", "needs_review", "escalate"}:
            # Non-promotable but already dispositioned → leave for stage sync (triaged).
            skipped += 1
            continue
        if disposition == "needs_review" and _severity_rank(alert.get("severity")) < 3:
            skipped += 1
            continue

        # Link siblings by title prefix / host
        sibling_ids: list[uuid.UUID] = [alert_id]
        sibs = (
            await db.execute(
                text(
                    """
                    SELECT id FROM alerts
                     WHERE tenant_id = :tid
                       AND created_at >= :since
                       AND id <> :id
                       AND case_id IS NULL
                       AND COALESCE(disposition, '') NOT IN ('false_positive','benign','benign_true_positive')
                       AND left(title, 40) = left(:title, 40)
                     ORDER BY created_at DESC
                     LIMIT 20
                    """
                ).bindparams(
                    tid=tenant_id,
                    since=since,
                    id=alert_id,
                    title=str(alert.get("title") or ""),
                )
            )
        ).fetchall()
        sibling_ids.extend(r[0] for r in sibs)

        now = datetime.now(UTC)
        title = str(alert.get("title") or "Agentic SOC case")[:500]
        severity = str(alert.get("severity") or "medium")
        if severity not in {"info", "low", "medium", "high", "critical"}:
            severity = "medium"
        description = (
            f"Auto-created by Agentic SOC 24h funnel backfill.\n"
            f"Disposition: {disposition}\n"
            f"Primary alert: {alert_id}\n"
            f"Linked alerts: {len(sibling_ids)}\n"
        )
        # Attach to an existing open agentic case with the same title instead
        # of creating one near-identical case per uncased alert.
        existing = (
            await db.execute(
                text(
                    """
                    SELECT id, alert_ids FROM aisoc_cases
                     WHERE tenant_id = :tid
                       AND title = :title
                       AND status NOT IN ('resolved', 'closed')
                       AND created_by IN ('agentic-funnel', 'agentic-funnel-backfill')
                     ORDER BY opened_at ASC
                     LIMIT 1
                    """
                ).bindparams(tid=tenant_id, title=title)
            )
        ).fetchone()
        created_new = existing is None
        if existing is not None:
            case_id = existing[0]
            prior = list(existing[1] or [])
            merged = list(dict.fromkeys([*prior, *sibling_ids]))
            await db.execute(
                text(
                    """
                    UPDATE aisoc_cases
                       SET alert_ids = CAST(:alert_ids AS UUID[]),
                           updated_at = :now
                     WHERE id = :id AND tenant_id = :tid
                    """
                ).bindparams(
                    id=case_id,
                    tid=tenant_id,
                    alert_ids=[str(x) for x in merged],
                    now=now,
                )
            )
        else:
            case_id = uuid.uuid4()
            await db.execute(
                text(
                    """
                    INSERT INTO aisoc_cases (
                        id, tenant_id, title, description, severity, status,
                        alert_ids, tags, opened_at, created_at, updated_at, created_by
                    ) VALUES (
                        :id, :tid, :title, :description, :severity, 'new',
                        CAST(:alert_ids AS UUID[]), CAST(:tags AS JSONB),
                        :now, :now, :now, 'agentic-funnel-backfill'
                    )
                    """
                ).bindparams(
                    id=case_id,
                    tid=tenant_id,
                    title=title,
                    description=description,
                    severity=severity,
                    alert_ids=[str(x) for x in sibling_ids],
                    tags=json.dumps({"agentic-promoted": True, "reportable": True, "source": "backfill"}),
                    now=now,
                )
            )
        from app.services.funnel_stages import passes_ready_for_jira_stage

        next_stage = (
            "ready_for_jira"
            if passes_ready_for_jira_stage(
                disposition=disposition,
                severity=severity,
                confidence=alert.get("confidence") or alert.get("ai_score"),
                case_id=case_id,
                tags=alert.get("tags"),
                rule_id=alert.get("rule_id") if isinstance(alert.get("rule_id"), str) else None,
                rule_name=alert.get("rule_name") if isinstance(alert.get("rule_name"), str) else None,
                mitre_techniques=alert.get("mitre_techniques")
                if isinstance(alert.get("mitre_techniques"), list)
                else None,
                ai_summary=alert.get("ai_summary") if isinstance(alert.get("ai_summary"), str) else None,
                narrative=alert.get("narrative") if isinstance(alert.get("narrative"), str) else None,
            )
            else "cased"
        )
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET case_id = :cid,
                       disposition = COALESCE(NULLIF(disposition, ''), :d),
                       tags = COALESCE(tags, '[]'::jsonb) || CAST(:tag AS JSONB),
                       status = CASE WHEN status IN ('new','triaging') THEN 'in_progress' ELSE status END,
                       funnel_stage = :stage,
                       updated_at = now()
                 WHERE tenant_id = :tid AND id = ANY(CAST(:ids AS UUID[]))
                """
            ).bindparams(
                cid=case_id,
                d=disposition,
                tag=json.dumps(["agentic-promoted", "reportable"]),
                tid=tenant_id,
                ids=[str(x) for x in sibling_ids],
                stage=next_stage,
            )
        )
        if created_new:
            for task in _tasks_for(alert, host, src, dst):
                await db.execute(
                    text(
                        """
                        INSERT INTO aisoc_case_tasks
                          (id, case_id, tenant_id, title, status, created_at, updated_at, created_by)
                        VALUES
                          (:id, :cid, :tid, :title, 'todo', :now, :now, 'agentic-funnel-backfill')
                        """
                    ).bindparams(id=uuid.uuid4(), cid=case_id, tid=tenant_id, title=task["title"][:500], now=now)
                )
                if task.get("description"):
                    await db.execute(
                        text(
                            """
                            INSERT INTO aisoc_case_comments
                              (id, case_id, tenant_id, author, body, is_system, created_at)
                            VALUES
                              (:id, :cid, :tid, 'agentic-funnel-backfill', :body, TRUE, :now)
                            """
                        ).bindparams(
                            id=uuid.uuid4(),
                            cid=case_id,
                            tid=tenant_id,
                            body=f"{task['title']}\n\n{task['description']}"[:8000],
                            now=now,
                        )
                    )
            cases_created += 1
        linked += len(sibling_ids)
        reportable.append(
            {
                "case_id": str(case_id),
                "title": title,
                "severity": severity,
                "disposition": disposition,
                "alert_count": len(sibling_ids),
                "check": (f"Review {src} ↔ {dst}" if src and dst else f"Review {host or title}"),
                "reused_existing_case": not created_new,
            }
        )

    stage_sync = await sync_legacy_funnel_stages(db, tenant_id=tenant_id, since=since)
    await db.commit()
    return {
        "window_hours": hours,
        "alerts_scanned": len(rows),
        "false_positive_tagged": fp_tagged,
        "cases_created": cases_created,
        "alerts_linked": linked,
        "skipped": skipped,
        "reportable": reportable,
        "stage_sync": stage_sync,
        "stages_updated": int(sum(stage_sync.values())),
    }


async def list_reportable(db: AsyncSession, *, tenant_id: uuid.UUID, hours: int = 24) -> dict[str, Any]:
    """Open/reportable cases + unresolved TPs for the SOC handover list."""
    since = datetime.now(UTC) - timedelta(hours=max(1, min(hours, 168)))
    cases = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, status, alert_ids, tags, opened_at, description
                  FROM aisoc_cases
                 WHERE tenant_id = :tid
                   AND opened_at >= :since
                   AND status NOT IN ('resolved', 'closed')
                 ORDER BY
                   CASE severity
                     WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                     WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
                   END,
                   opened_at DESC
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    ).mappings().all()
    fps = (
        await db.execute(
            text(
                """
                SELECT COUNT(*) AS n FROM alerts
                 WHERE tenant_id = :tid AND created_at >= :since
                   AND (
                     disposition IN ('false_positive','benign','benign_true_positive')
                     OR tags @> '["false_positive"]'::jsonb
                   )
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    ).scalar_one()
    total = (
        await db.execute(
            text("SELECT COUNT(*) FROM alerts WHERE tenant_id = :tid AND created_at >= :since").bindparams(
                tid=tenant_id, since=since
            )
        )
    ).scalar_one()
    items = []
    for c in cases:
        tags = c.get("tags") or {}
        items.append(
            {
                "case_id": str(c["id"]),
                "title": c["title"],
                "severity": c["severity"],
                "status": c["status"],
                "alert_count": len(c.get("alert_ids") or []),
                "reportable": bool(isinstance(tags, dict) and tags.get("reportable"))
                or (isinstance(tags, list) and "reportable" in tags),
                "opened_at": c["opened_at"].isoformat() if c.get("opened_at") else None,
                "summary": (c.get("description") or "")[:400],
            }
        )
    return {
        "window_hours": hours,
        "alerts_total": int(total or 0),
        "false_positives": int(fps or 0),
        "reportable_cases": items,
        "reportable_count": len(items),
    }


async def funnel_board(db: AsyncSession, *, tenant_id: uuid.UUID, hours: int = 24) -> dict[str, Any]:
    """Stage counts + sample alerts for the SOC Funnel UI board."""
    from app.services.funnel_stages import BOARD_ORDER, STAGE_LABELS

    since = datetime.now(UTC) - timedelta(hours=max(1, min(hours, 168)))
    counts_rows = (
        await db.execute(
            text(
                """
                SELECT COALESCE(funnel_stage, 'ingested') AS stage, COUNT(*)::int AS n
                  FROM alerts
                 WHERE tenant_id = :tid AND created_at >= :since
                 GROUP BY 1
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    ).mappings().all()
    count_map = {str(r["stage"]): int(r["n"]) for r in counts_rows}
    stages = [
        {
            "id": stage,
            "label": STAGE_LABELS.get(stage, stage),
            "count": count_map.get(stage, 0),
        }
        for stage in BOARD_ORDER
    ]
    samples = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, status, disposition, funnel_stage,
                       confidence, case_id, created_at
                  FROM alerts
                 WHERE tenant_id = :tid AND created_at >= :since
                 ORDER BY created_at DESC
                 LIMIT 80
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    ).mappings().all()
    by_stage: dict[str, list[dict[str, Any]]] = {s: [] for s in BOARD_ORDER}
    for row in samples:
        stage = str(row.get("funnel_stage") or "ingested")
        if stage not in by_stage:
            by_stage[stage] = []
        if len(by_stage[stage]) >= 8:
            continue
        by_stage[stage].append(
            {
                "id": str(row["id"]),
                "title": row["title"],
                "severity": row["severity"],
                "status": row["status"],
                "disposition": row.get("disposition"),
                "funnel_stage": stage,
                "confidence": row.get("confidence"),
                "case_id": str(row["case_id"]) if row.get("case_id") else None,
                "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
            }
        )
    total = sum(s["count"] for s in stages)
    suppressed = count_map.get("suppressed", 0)
    ready = count_map.get("ready_for_jira", 0) + count_map.get("jira_pushed", 0)
    return {
        "window_hours": hours,
        "alerts_total": total,
        "stages": stages,
        "samples_by_stage": by_stage,
        "ratios": {
            "suppression_rate": round(suppressed / total, 4) if total else 0.0,
            "ready_for_jira_rate": round(ready / total, 4) if total else 0.0,
        },
    }
