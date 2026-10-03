"""Promote escalated alerts into ``aisoc_cases`` with linked siblings + tasks.

Closes the agentic funnel gap after auto-triage: true_positive / high-severity
needs_review alerts become Cases, related alerts (shared host/IP) are linked,
false-positive tags are applied on auto-close, and Case tasks carry concrete
investigation steps (including Splunk SPL pivots when src/dst IPs exist).

Fail-soft and idempotent — never wedges the fused-alert consumer.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.agents.dispositions import (
    AUTO_CLOSEABLE_DISPOSITIONS,
    FALSE_POSITIVE,
    NEEDS_REVIEW,
    TRUE_POSITIVE,
    normalize_disposition,
)
from app.funnel.stages import (
    CASED,
    READY_FOR_JIRA,
    SUPPRESSED,
    passes_investigation_gate,
    passes_ready_for_jira_stage,
)
from app.investigator import ledger as ledger_module
from app.models.state import InvestigationState

logger = structlog.get_logger()

_TAG_FP = "false_positive"
_TAG_PROMOTED = "agentic-promoted"
_TAG_REPORTABLE = "reportable"
_LOOKBACK_HOURS = int(os.getenv("AISOC_AGENT_CASE_LINK_LOOKBACK_HOURS", "48"))
_SEVERITY_FLOOR = {
    s.strip().lower()
    for s in os.getenv("AISOC_AGENT_CASE_SEVERITIES", "medium,high,critical").split(",")
    if s.strip()
}


def auto_case_enabled() -> bool:
    """On by default; disable with ``AISOC_AGENT_AUTO_CASE=0``."""
    return os.getenv("AISOC_AGENT_AUTO_CASE", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def should_promote(*, verdict: str, severity: str | None, confidence: float) -> bool:
    """Decide whether an escalated alert becomes a Case (investigation gate)."""
    disposition = normalize_disposition(verdict, default=NEEDS_REVIEW)
    if disposition in AUTO_CLOSEABLE_DISPOSITIONS:
        return False
    # Product funnel P1: shared gate (high/critical OR medium@≥0.70 for needs_review;
    # all true_positive / escalate / likely_tp promote).
    if passes_investigation_gate(
        disposition=disposition, severity=severity, confidence=confidence
    ):
        return True
    # Preserve prior TP→case behaviour for low/info TPs outside the severity floor.
    sev = (severity or "medium").strip().lower()
    if disposition == TRUE_POSITIVE and (sev in _SEVERITY_FLOOR or sev in {"low", "info"}):
        return True
    return False


def _build_tasks(
    state: InvestigationState,
    *,
    alert: dict[str, Any],
) -> list[dict[str, str]]:
    """Investigation checklist rows for ``aisoc_case_tasks``."""
    tasks: list[dict[str, str]] = []
    src = alert.get("src_ip") or (state.raw_alert or {}).get("src_ip")
    dst = alert.get("dst_ip") or (state.raw_alert or {}).get("dst_ip")
    host = alert.get("hostname") or (state.raw_alert or {}).get("hostname")
    user = alert.get("username") or (state.raw_alert or {}).get("username")
    title = str(alert.get("title") or state.alert_summary or "alert")

    if src and dst:
        tasks.append(
            {
                "title": f"Investigate traffic between {src} and {dst}",
                "description": (
                    f"Password-spray / lateral / C2 pivot candidate for «{title}». "
                    f"In Splunk run a bounded search correlating {src} ↔ {dst} "
                    f"(auth failures, unusual ports, shared user agents)."
                ),
            }
        )
        tasks.append(
            {
                "title": f"SPL: pivot {src} ↔ {dst}",
                "description": (
                    f'index=* (src="{src}" OR dest="{dst}" OR src_ip="{src}" OR dest_ip="{dst}") '
                    f"earliest=-24h | stats count by src, dest, user, sourcetype | sort -count"
                ),
            }
        )
    if host:
        tasks.append(
            {
                "title": f"Review host activity on {host}",
                "description": (
                    f"Check process, auth, and network telemetry for {host} in the alert window. "
                    f'SPL: index=* host="{host}" earliest=-24h | stats count by sourcetype, user'
                ),
            }
        )
    if user:
        tasks.append(
            {
                "title": f"Validate identity activity for {user}",
                "description": (
                    f"Confirm whether {user} is expected to authenticate from the observed sources. "
                    f'SPL: index=* user="{user}" earliest=-24h | stats count by src, dest, action'
                ),
            }
        )
    for finding in list(state.findings or [])[:8]:
        text = str(finding).strip()
        if not text:
            continue
        tasks.append({"title": f"Review finding: {text[:120]}", "description": text[:2000]})
    for action in list(state.proposed_actions or [])[:8]:
        if isinstance(action, dict):
            desc = str(action.get("description") or "")
            atype = str(action.get("action_type") or "action")
        else:
            desc = str(getattr(action, "description", "") or "")
            atype = str(getattr(action, "action_type", "") or "action")
        tasks.append(
            {
                "title": f"Recommended: {atype}"[:500],
                "description": (desc or atype)[:2000],
            }
        )
    if not tasks:
        tasks.append(
            {
                "title": "Triage and decide reportability",
                "description": (
                    f"Auto-promoted from agentic funnel. Confirm whether «{title}» "
                    "should be reported to stakeholders or closed as noise."
                ),
            }
        )
    # Deduplicate by title
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for t in tasks:
        key = t["title"].lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out[:12]


async def tag_false_positive(alert_id: str | None, tenant_id: uuid.UUID) -> bool:
    """Append the ``false_positive`` tag on an auto-closed alert."""
    pool = await ledger_module.get_pool()
    if pool is None or not alert_id:
        return False
    try:
        alert_uuid = uuid.UUID(str(alert_id))
    except (ValueError, TypeError):
        return False
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE alerts
                   SET tags = (
                         SELECT COALESCE(jsonb_agg(DISTINCT v), '[]'::jsonb)
                           FROM jsonb_array_elements_text(
                             COALESCE(tags, '[]'::jsonb) || $3::jsonb
                           ) AS t(v)
                       ),
                       funnel_stage = $4,
                       updated_at = now()
                 WHERE id = $1 AND tenant_id = $2
                """,
                alert_uuid,
                tenant_id,
                json.dumps([_TAG_FP]),
                SUPPRESSED,
            )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("case_promoter.fp_tag_failed", alert_id=str(alert_id), error=str(exc))
        return False


async def promote_to_case(state: InvestigationState, *, message: dict[str, Any] | None = None) -> str | None:
    """Create/link an ``aisoc_cases`` row for an escalated alert. Returns case id."""
    if not auto_case_enabled():
        return None
    alert = {}
    if isinstance(message, dict) and isinstance(message.get("alert"), dict):
        alert = message["alert"]
    raw = state.raw_alert or {}
    severity = str(alert.get("severity") or raw.get("severity") or "medium")
    verdict = normalize_disposition(str(state.verdict or NEEDS_REVIEW), default=NEEDS_REVIEW)
    if not should_promote(verdict=verdict, severity=severity, confidence=float(state.confidence or 0.0)):
        return None

    alert_id = str(raw.get("id") or alert.get("id") or "")
    if not alert_id:
        return None
    try:
        alert_uuid = uuid.UUID(alert_id)
    except (ValueError, TypeError):
        return None

    pool = await ledger_module.get_pool()
    if pool is None:
        return None

    title = str(alert.get("title") or state.alert_summary or "Agentic SOC case")[:500]
    mitre = alert.get("mitre_techniques") or raw.get("mitre_techniques") or []
    if not isinstance(mitre, list):
        mitre = []
    findings_blob = "\n".join(f"- {f}" for f in (state.findings or [])[:12])
    description = (
        f"Auto-created by Agentic SOC funnel.\n"
        f"Disposition: {verdict} (confidence={float(state.confidence or 0.0):.2f})\n"
        f"Severity: {severity}\n\n"
        f"Summary: {state.alert_summary or title}\n\n"
        f"Investigation notes:\n{findings_blob or '- (pending enrichment)'}\n"
    )[:8000]

    tasks = _build_tasks(state, alert={**raw, **alert, "title": title})
    now = datetime.now(UTC)
    since = now - timedelta(hours=_LOOKBACK_HOURS)

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                existing = await conn.fetchval(
                    "SELECT case_id FROM alerts WHERE id = $1 AND tenant_id = $2",
                    alert_uuid,
                    state.tenant_id,
                )
                if existing:
                    return str(existing)

                # Related alerts: shared host or IP in lookback, not auto-closed FP.
                host = alert.get("hostname") or raw.get("hostname")
                src = alert.get("src_ip") or raw.get("src_ip")
                related_rows = await conn.fetch(
                    """
                    SELECT id FROM alerts
                     WHERE tenant_id = $1
                       AND created_at >= $2
                       AND id <> $3
                       AND case_id IS NULL
                       AND COALESCE(disposition, '') NOT IN ('false_positive', 'benign', 'benign_true_positive')
                       AND (
                             ($4::text IS NOT NULL AND (
                                 COALESCE(affected_hosts, '[]'::jsonb) @> to_jsonb(ARRAY[$4::text])
                              OR COALESCE(entities, '[]'::jsonb) @> jsonb_build_array(jsonb_build_object('type','host','value',$4::text))
                             ))
                          OR ($5::text IS NOT NULL AND (
                                 COALESCE(affected_ips, '[]'::jsonb) @> to_jsonb(ARRAY[$5::text])
                              OR COALESCE(iocs, '[]'::jsonb) @> jsonb_build_array(jsonb_build_object('type','ip','value',$5::text))
                             ))
                       )
                     ORDER BY created_at DESC
                     LIMIT 25
                    """,
                    state.tenant_id,
                    since,
                    alert_uuid,
                    str(host) if host else None,
                    str(src) if src else None,
                )
                # Fallback if hostname/src columns differ — match title prefix rules
                if not related_rows and title:
                    related_rows = await conn.fetch(
                        """
                        SELECT id FROM alerts
                         WHERE tenant_id = $1
                           AND created_at >= $2
                           AND id <> $3
                           AND case_id IS NULL
                           AND COALESCE(disposition, '') NOT IN ('false_positive', 'benign', 'benign_true_positive')
                           AND left(title, 40) = left($4, 40)
                         ORDER BY created_at DESC
                         LIMIT 15
                        """,
                        state.tenant_id,
                        since,
                        alert_uuid,
                        title,
                    )

                linked_ids = [alert_uuid] + [r["id"] for r in related_rows]
                case_id = uuid.uuid4()
                tags = {_TAG_PROMOTED: True, _TAG_REPORTABLE: True, "source": "agentic_funnel"}
                await conn.execute(
                    """
                    INSERT INTO aisoc_cases (
                        id, tenant_id, title, description, severity, status,
                        mitre_techniques, alert_ids, tags,
                        opened_at, created_at, updated_at, created_by
                    ) VALUES (
                        $1, $2, $3, $4, $5, 'new',
                        $6::jsonb, $7::uuid[], $8::jsonb,
                        $9, $9, $9, 'agentic-funnel'
                    )
                    """,
                    case_id,
                    state.tenant_id,
                    title,
                    description,
                    severity if severity in {"info", "low", "medium", "high", "critical"} else "medium",
                    json.dumps([str(m) for m in mitre]),
                    linked_ids,
                    json.dumps(tags),
                    now,
                )
                next_stage = (
                    READY_FOR_JIRA
                    if passes_ready_for_jira_stage(
                        disposition=verdict,
                        severity=severity,
                        confidence=float(state.confidence or 0.0),
                        mitre_techniques=mitre,
                        findings=list(state.findings or []),
                    )
                    else CASED
                )
                await conn.execute(
                    """
                    UPDATE alerts
                       SET case_id = $1,
                           tags = (
                             SELECT COALESCE(jsonb_agg(DISTINCT v), '[]'::jsonb)
                               FROM jsonb_array_elements_text(
                                 COALESCE(tags, '[]'::jsonb) || $4::jsonb
                               ) AS t(v)
                           ),
                           status = CASE WHEN status IN ('new', 'triaging') THEN 'in_progress' ELSE status END,
                           funnel_stage = $5,
                           updated_at = now()
                     WHERE tenant_id = $2 AND id = ANY($3::uuid[])
                    """,
                    case_id,
                    state.tenant_id,
                    linked_ids,
                    json.dumps([_TAG_PROMOTED, _TAG_REPORTABLE]),
                    next_stage,
                )
                for task in tasks:
                    await conn.execute(
                        """
                        INSERT INTO aisoc_case_tasks
                          (id, case_id, tenant_id, title, status, created_at, updated_at, created_by)
                        VALUES
                          ($1, $2, $3, $4, 'todo', $5, $5, 'agentic-funnel')
                        """,
                        uuid.uuid4(),
                        case_id,
                        state.tenant_id,
                        task["title"][:500],
                        now,
                    )
                    # Store SPL / description as a system comment when present
                    if task.get("description"):
                        await conn.execute(
                            """
                            INSERT INTO aisoc_case_comments
                              (id, case_id, tenant_id, author, body, is_system, created_at)
                            VALUES
                              ($1, $2, $3, 'agentic-funnel', $4, TRUE, $5)
                            """,
                            uuid.uuid4(),
                            case_id,
                            state.tenant_id,
                            f"{task['title']}\n\n{task['description']}"[:8000],
                            now,
                        )
        logger.info(
            "case_promoter.created",
            case_id=str(case_id),
            alert_id=alert_id,
            linked=len(linked_ids),
            tasks=len(tasks),
            verdict=verdict,
        )
        return str(case_id)
    except Exception as exc:  # noqa: BLE001 — never wedge triage
        logger.warning("case_promoter.failed", alert_id=alert_id, error=str(exc))
        return None
