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
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.campaign_case import (
    campaign_case_title,
    campaign_entities,
    campaign_tags,
    infer_attack_theme,
    primary_campaign_key,
)
from app.services.campaign_correlation import (
    campaign_temporal_window_seconds,
    extract_alert_hosts,
    is_candidate_eligible,
    is_risk_supporting_alert,
    is_seed_eligible,
    score_campaign_link,
    select_campaign_siblings,
    summarize_correlation_decisions,
)
from app.services.runbook.emitters import emit_case_created

logger = structlog.get_logger()

_SIBLING_CAP = 100
# Max lookback for board / backfill / reportable (30 days). A 7d cap left
# multi-day ingest floods stuck at ``ingested`` with no way to advance them.
FUNNEL_MAX_WINDOW_HOURS = 720
# Soft display-dedupe runs on every board load (and backfill). Throttle keeps
# concurrent UI refreshes from re-scanning the whole alerts table too often.
_AUTO_DEDUPE_INTERVAL_S = 15.0
_last_auto_dedupe_monotonic: dict[str, float] = {}


def _window_since(hours: int) -> datetime:
    """Clamp ``hours`` into ``[1, FUNNEL_MAX_WINDOW_HOURS]`` and return UTC since."""
    return datetime.now(UTC) - timedelta(hours=max(1, min(int(hours), FUNNEL_MAX_WINDOW_HOURS)))

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


_WEAK_AUTO_TP = re.compile(
    r"(?i)powershell|scriptblock|invoke-command|invoke\s*command|"
    r"defender\s*exclusion|short-lived\s*account|uac\s*bypass|"
    r"unapproved\s*port|policy\s*disabled"
)


def classify_backfill(alert: dict[str, Any]) -> str:
    """Heuristic disposition for alerts that never went through auto-triage.

    High/critical severity alone is NOT true_positive — that previously forced
    PowerShell/admin noise and weak detections into TP and then into megacases.
    """
    existing = (alert.get("disposition") or "").strip().lower()
    if existing:
        return existing
    title = str(alert.get("title") or "")
    sev = str(alert.get("severity") or "medium").lower()
    if is_risk_supporting_alert(alert):
        # Risk rollups inherit context; do not auto-declare independent TP attacks.
        return "needs_review"
    if sev in {"low", "info"} and _NOISE_HINTS.search(title):
        return "false_positive"
    # Ambiguous admin / living-off-the-land detections need human review even
    # when severity is high (ScriptBlock Invoke-*, Defender exclusion, etc.).
    if _WEAK_AUTO_TP.search(title):
        return "needs_review"
    if _ATTACK_HINTS.search(title) and sev in {"high", "critical", "medium", "low"}:
        return "true_positive"
    if sev in {"high", "critical"}:
        return "needs_review"
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
                   AND funnel_stage IS DISTINCT FROM 'deduplicated'
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
    # Evidence bar aligned with passes_ready_for_jira_stage: severity alone
    # is insufficient — need investigation prose OR conf≥70 + rule/MITRE metadata.
    _evidence_sql = """
                      length(COALESCE(ai_summary, '')) >= 100
                   OR length(COALESCE(narrative, '')) >= 200
                   OR (
                        COALESCE(
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
    """
    counts["ready_for_jira"] = _n(
        await db.execute(
            text(
                f"""
                UPDATE alerts
                   SET funnel_stage = 'ready_for_jira', updated_at = now()
                 WHERE tenant_id = :tid
                   AND created_at >= :since
                   AND case_id IS NOT NULL
                   AND disposition IN ('true_positive','escalate','likely_tp')
                   AND funnel_stage NOT IN ('jira_pushed','ready_for_jira')
                   AND ({_evidence_sql})
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    )
    # Demote Cases previously marked ready_for_jira on severity alone.
    demoted = _n(
        await db.execute(
            text(
                f"""
                UPDATE alerts
                   SET funnel_stage = 'cased', updated_at = now()
                 WHERE tenant_id = :tid
                   AND created_at >= :since
                   AND case_id IS NOT NULL
                   AND funnel_stage = 'ready_for_jira'
                   AND NOT ({_evidence_sql})
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
    since = _window_since(hours)
    rows = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, status, disposition, case_id, tags,
                       affected_hosts, affected_ips, affected_users, raw_event,
                       created_at, event_time, llm_payload, iocs,
                       rule_id, rule_name, mitre_techniques, mitre_tactics,
                       confidence, ai_score, ai_summary, narrative
                  FROM alerts
                 WHERE tenant_id = :tid AND created_at >= :since
                 ORDER BY created_at DESC
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    ).mappings().all()
    # Materialize once so sibling scoring can see the full 24h (or window) set
    # without re-querying with a loose OR(host|ip|user) that false-merged campaigns.
    window_alerts: list[dict[str, Any]] = [dict(r) for r in rows]

    fp_tagged = 0
    cases_created = 0
    linked = 0
    reportable: list[dict[str, Any]] = []
    # New cases are collected here and written to the Runbook ledger AFTER the
    # funnel's own commit: ``emit_case_created`` commits, and committing inside
    # the loop would durably land half a backfill if a later alert failed.
    created_cases: list[dict[str, Any]] = []
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

        # Stamp classified disposition onto the in-memory row so seed/candidate
        # eligibility sees a real disposition (never admit on missing/unknown).
        alert["disposition"] = disposition
        seed_ok, seed_why = is_seed_eligible(alert)
        if not seed_ok:
            skipped += 1
            logger.debug(
                "campaign_seed_ineligible",
                alert_id=str(alert_id),
                reason=seed_why,
            )
            continue

        # Attack-campaign siblings: scored entity+temporal correlation only.
        # Never OR-match host|ip|user across the whole window (that built megacases).
        entities = campaign_entities(alert, raw if isinstance(raw, dict) else {})
        theme = infer_attack_theme(
            title=str(alert.get("title") or ""),
            mitre_tactics=alert.get("mitre_tactics") if isinstance(alert.get("mitre_tactics"), list) else None,
            mitre_techniques=alert.get("mitre_techniques")
            if isinstance(alert.get("mitre_techniques"), list)
            else None,
            raw_alert=raw if isinstance(raw, dict) else {},
        )
        camp_key = primary_campaign_key(theme, entities)

        uncased_candidates = []
        for a in window_alerts:
            if str(a.get("id")) == str(alert_id):
                continue
            # Apply classified disposition for eligibility when row is blank.
            if not str(a.get("disposition") or "").strip():
                a = dict(a)
                a["disposition"] = classify_backfill(a)
            ok, _why = is_candidate_eligible(a)
            if ok:
                uncased_candidates.append(a)
        accepted_sibs, link_decisions = select_campaign_siblings(
            alert,
            uncased_candidates,
            temporal_window_seconds=campaign_temporal_window_seconds(hours),
            limit=_SIBLING_CAP,
        )
        # Risk seeds stay solo — supporting rollups must not open intrusion megacases.
        if is_risk_supporting_alert(alert):
            accepted_sibs = []
        sibling_ids: list[uuid.UUID] = [alert_id]
        sibling_ids.extend(
            a["id"] if isinstance(a["id"], uuid.UUID) else uuid.UUID(str(a["id"]))
            for a in accepted_sibs
        )
        correlation_audit = {
            "algorithm_version": "campaign-corr:v2",
            "seed_alert_id": str(alert_id),
            "seed_hosts": extract_alert_hosts(alert),
            "discovery": summarize_correlation_decisions(link_decisions),
            "linked": [
                d for d in link_decisions if d.get("linked")
            ][:_SIBLING_CAP],
            "rejected_sample": [
                d for d in link_decisions if not d.get("linked")
            ][:20],
        }

        now = datetime.now(UTC)
        linked_n = len(sibling_ids)
        title = campaign_case_title(theme, entities, linked_alert_count=linked_n)
        severity = str(alert.get("severity") or "medium")
        if severity not in {"info", "low", "medium", "high", "critical"}:
            severity = "medium"
        entity_bits = ", ".join(f"{k}:{v}" for k, v in entities[:6]) or "(no strong entity)"
        link_bits = "; ".join(
            f"{d.get('alert_id')}: {d.get('decision_reason', '')[:120]}"
            for d in correlation_audit["linked"][:8]
        ) or "solo alert (no scored siblings)"
        case_kind = "attack-campaign" if linked_n > 1 else "incident"
        description = (
            f"Auto-created by Agentic SOC funnel backfill as an {case_kind} case.\n"
            f"Theme: {theme}\n"
            f"Entities: {entity_bits}\n"
            f"Disposition (seed only): {disposition}\n"
            f"Seed alert: {alert.get('title')}\n"
            f"Linked alerts: {linked_n}\n"
            f"Correlation: {link_bits}\n"
        )
        tags = campaign_tags(
            theme=theme,
            campaign_key=camp_key,
            source="backfill",
            linked_alert_count=linked_n,
        )
        tags["correlation"] = correlation_audit
        existing = None
        # Reuse requires SAME campaign_key AND an evidenced v2 link from this
        # seed to the existing case seed. Same key alone previously merged
        # hundreds of solo alerts into one megacase (theme|host buckets).
        if camp_key:
            existing_row = (
                await db.execute(
                    text(
                        """
                        SELECT id, alert_ids FROM aisoc_cases
                         WHERE tenant_id = :tid
                           AND status NOT IN ('resolved', 'closed')
                           AND created_by IN ('agentic-funnel', 'agentic-funnel-backfill')
                           AND opened_at >= :since
                           AND tags->>'campaign_key' = :ckey
                         ORDER BY opened_at ASC
                         LIMIT 1
                        """
                    ).bindparams(tid=tenant_id, since=since, ckey=camp_key)
                )
            ).fetchone()
            if existing_row is not None:
                prior_ids = list(existing_row[1] or [])
                existing_seed_id = prior_ids[0] if prior_ids else None
                existing_seed = None
                if existing_seed_id is not None:
                    existing_seed = next(
                        (
                            a
                            for a in window_alerts
                            if str(a.get("id")) == str(existing_seed_id)
                        ),
                        None,
                    )
                    if existing_seed is None:
                        existing_seed = (
                            await db.execute(
                                text(
                                    """
                                    SELECT id, title, severity, disposition, case_id, tags,
                                           affected_hosts, affected_ips, affected_users, raw_event,
                                           created_at, event_time, llm_payload, iocs,
                                           rule_id, rule_name, mitre_techniques, mitre_tactics,
                                           confidence, ai_score, funnel_stage
                                      FROM alerts
                                     WHERE tenant_id = :tid AND id = :aid
                                     LIMIT 1
                                    """
                                ).bindparams(tid=tenant_id, aid=existing_seed_id)
                            )
                        ).mappings().first()
                        existing_seed = dict(existing_seed) if existing_seed else None
                can_reuse = False
                if existing_seed is not None and str(existing_seed.get("id")) != str(alert_id):
                    link = score_campaign_link(
                        existing_seed,
                        alert,
                        temporal_window_seconds=campaign_temporal_window_seconds(hours),
                    )
                    can_reuse = bool(link.linked)
                if can_reuse:
                    existing = existing_row
        created_new = existing is None
        if existing is not None:
            case_id = existing[0]
            prior = list(existing[1] or [])
            # Only merge this seed + scored siblings — never dump unrelated same-key solos.
            merged = list(dict.fromkeys([*prior, *sibling_ids]))
            await db.execute(
                text(
                    """
                    UPDATE aisoc_cases
                       SET alert_ids = CAST(:alert_ids AS UUID[]),
                           tags = COALESCE(tags, '{}'::jsonb) || CAST(:corr AS jsonb),
                           updated_at = :now
                     WHERE id = :id AND tenant_id = :tid
                    """
                ).bindparams(
                    id=case_id,
                    tid=tenant_id,
                    alert_ids=[str(x) for x in merged],
                    corr=json.dumps({"correlation": correlation_audit}),
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
                    tags=json.dumps(tags),
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
        # Stamp case membership for seed + scored siblings. Do NOT copy the seed
        # disposition onto siblings (that forced 12× true_positive without evidence).
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET case_id = :cid,
                       tags = COALESCE(tags, '[]'::jsonb) || CAST(:tag AS JSONB),
                       status = CASE WHEN status IN ('new','triaging') THEN 'in_progress' ELSE status END,
                       funnel_stage = CASE
                         WHEN id = :seed THEN CAST(:stage AS text)
                         ELSE COALESCE(NULLIF(funnel_stage, ''), 'cased')
                       END,
                       updated_at = now()
                 WHERE tenant_id = :tid AND id = ANY(CAST(:ids AS UUID[]))
                """
            ).bindparams(
                cid=case_id,
                tag=json.dumps(["agentic-promoted", "reportable"]),
                tid=tenant_id,
                ids=[str(x) for x in sibling_ids],
                seed=alert_id,
                stage=next_stage,
            )
        )
        # Persist seed disposition only on the seed row when missing.
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET disposition = COALESCE(NULLIF(disposition, ''), :d),
                       updated_at = now()
                 WHERE tenant_id = :tid AND id = :seed
                """
            ).bindparams(d=disposition, tid=tenant_id, seed=alert_id)
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
            created_cases.append(
                {
                    "case_id": case_id,
                    "title": title,
                    "severity": severity,
                    "disposition": disposition,
                    "alert_ids": [str(x) for x in sibling_ids],
                }
            )
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

    # Runbook: one "Case opened" row per case this run created. Each emission
    # commits its own row; failures are swallowed by the emitter so a ledger
    # problem never fails a backfill that already committed successfully.
    for created in created_cases:
        await emit_case_created(
            db,
            tenant_id=tenant_id,
            case_id=created["case_id"],
            case_title=str(created["title"]),
            alert_ids=list(created["alert_ids"]),
            actor_label="agentic-funnel-backfill",
            severity=created["severity"],
            disposition=created["disposition"],
        )

    # Soft display-dedupe into the Deduplicated column so analysts never need
    # the manual "Remove duplicates" click after a large Splunk wave.
    dedupe: dict[str, Any] = {}
    try:
        from app.services.exact_dedupe import dedupe_exact

        dedupe = await dedupe_exact(db, tenant_id=tenant_id, dry_run=False)
    except Exception as exc:  # noqa: BLE001 — dedupe must not fail the backfill
        logger.warning(
            "run_backfill.auto_dedupe_failed",
            error=str(exc).replace("\r", " ").replace("\n", " ")[:300],
        )
        await db.rollback()
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
        "dedupe": dedupe,
    }


async def list_reportable(db: AsyncSession, *, tenant_id: uuid.UUID, hours: int = 24) -> dict[str, Any]:
    """Open/reportable cases + unresolved TPs for the SOC handover list."""
    since = _window_since(hours)
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


async def _open_runbook_tasks(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    since: datetime,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    """Open Runbook tasks per alert and per funnel stage.

    A stage column with 50 alerts is a number; the same column with "37 of them are
    waiting on an analyst" is a diagnosis. The Runbook owns these rows, so this
    reads them rather than duplicating the queue.

    Degrades to empty maps when ``runbook_tasks`` is absent (a deployment that has
    not run migration 064): a missing badge must never break the board.
    """
    try:
        rows = (
            await db.execute(
                text(
                    """
                    SELECT t.alert_id::text AS alert_id,
                           t.task_type,
                           t.title,
                           t.status,
                           COALESCE(a.funnel_stage, 'ingested') AS stage
                      FROM runbook_tasks t
                      JOIN alerts a ON a.id = t.alert_id
                     WHERE t.tenant_id = :tid
                       AND t.status <> 'completed'
                       AND a.created_at >= :since
                     ORDER BY t.created_at
                     LIMIT 500
                    """
                ).bindparams(tid=tenant_id, since=since)
            )
        ).mappings().all()
    except Exception:  # noqa: BLE001 — the board must render even without this table
        logger.warning("soc_funnel.open_tasks_unavailable", exc_info=True)
        return {}, {}

    by_alert: dict[str, list[dict[str, Any]]] = {}
    by_stage: dict[str, int] = {}
    for row in rows:
        alert_id = str(row["alert_id"])
        by_alert.setdefault(alert_id, []).append(
            {
                "task_type": row["task_type"],
                "title": row["title"],
                "status": row["status"],
            }
        )
        stage = str(row["stage"] or "ingested")
        by_stage[stage] = by_stage.get(stage, 0) + 1
    return by_alert, by_stage


async def funnel_board(db: AsyncSession, *, tenant_id: uuid.UUID, hours: int = 24) -> dict[str, Any]:
    """Stage counts + sample alerts for the SOC Funnel UI board."""
    from app.services.funnel_stages import BOARD_ORDER, STAGE_LABELS

    # Soft-dedupe on a short throttle so the Deduplicated column stays current
    # without a manual "Remove duplicates" click after every Splunk wave.
    tid_key = str(tenant_id)
    now_mono = time.monotonic()
    last = _last_auto_dedupe_monotonic.get(tid_key, 0.0)
    if now_mono - last >= _AUTO_DEDUPE_INTERVAL_S:
        _last_auto_dedupe_monotonic[tid_key] = now_mono
        try:
            from app.services.exact_dedupe import dedupe_exact

            await dedupe_exact(db, tenant_id=tenant_id, dry_run=False)
        except Exception as exc:  # noqa: BLE001 — board must still render
            logger.warning(
                "funnel_board.auto_dedupe_failed",
                error=str(exc).replace("\r", " ").replace("\n", " ")[:300],
            )
            rb = getattr(db, "rollback", None)
            if callable(rb):
                try:
                    result = rb()
                    if hasattr(result, "__await__"):
                        await result  # type: ignore[misc]
                except Exception:  # noqa: BLE001
                    pass

    since = _window_since(hours)
    tasks_by_alert, tasks_by_stage = await _open_runbook_tasks(
        db, tenant_id=tenant_id, since=since
    )
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
            # Alerts in this stage that are waiting on a human in the Runbook.
            "open_tasks": tasks_by_stage.get(stage, 0),
        }
        for stage in BOARD_ORDER
    ]
    # One representative alert per (stage, title) plus how many share that title.
    # Column header count = all alerts; the card list is unique titles (not a bug).
    samples = (
        await db.execute(
            text(
                """
                WITH ranked AS (
                  SELECT id, title, severity, status, disposition, funnel_stage,
                         confidence, case_id, created_at,
                         COUNT(*) OVER (
                           PARTITION BY COALESCE(funnel_stage, 'ingested'), lower(trim(title))
                         ) AS same_title_count,
                         ROW_NUMBER() OVER (
                           PARTITION BY COALESCE(funnel_stage, 'ingested'), lower(trim(title))
                           ORDER BY created_at DESC
                         ) AS rn
                    FROM alerts
                   WHERE tenant_id = :tid AND created_at >= :since
                )
                SELECT id, title, severity, status, disposition, funnel_stage,
                       confidence, case_id, created_at, same_title_count
                  FROM ranked
                 WHERE rn = 1
                 ORDER BY created_at DESC
                 LIMIT 200
                """
            ).bindparams(tid=tenant_id, since=since)
        )
    ).mappings().all()
    by_stage: dict[str, list[dict[str, Any]]] = {s: [] for s in BOARD_ORDER}
    for row in samples:
        stage = str(row.get("funnel_stage") or "ingested")
        if stage not in by_stage:
            by_stage[stage] = []
        if len(by_stage[stage]) >= 12:
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
                "same_title_count": int(row.get("same_title_count") or 1),
                "open_tasks": tasks_by_alert.get(str(row["id"]), []),
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
