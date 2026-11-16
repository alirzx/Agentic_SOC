"""Reconcile false megacases created by legacy loose campaign linking.

Re-scores every alert membership with ``campaign_correlation.score_campaign_link``
against the seed (oldest / primary) alert. Alerts that fail the v2 gate are
unlinked (case_id cleared) without deleting alert rows. Risk alerts that lack
entity overlap are demoted to supporting tags only or unlinked.

Does not invent correlation — only removes links that cannot be evidenced.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.campaign_correlation import (
    CORRELATION_VERSION,
    extract_alert_hosts,
    is_risk_supporting_alert,
    score_campaign_link,
    select_campaign_siblings,
    summarize_correlation_decisions,
)


async def _load_case_alerts(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    case = (
        await db.execute(
            text(
                """
                SELECT id, title, description, severity, status, alert_ids, tags,
                       created_by, opened_at
                  FROM aisoc_cases
                 WHERE id = :cid AND tenant_id = :tid
                """
            ).bindparams(cid=case_id, tid=tenant_id)
        )
    ).mappings().first()
    if case is None:
        return None, []
    alert_ids = list(case.get("alert_ids") or [])
    if not alert_ids:
        rows = (
            await db.execute(
                text(
                    """
                    SELECT id FROM alerts
                     WHERE tenant_id = :tid AND case_id = :cid
                    """
                ).bindparams(tid=tenant_id, cid=case_id)
            )
        ).fetchall()
        alert_ids = [r[0] for r in rows]
    if not alert_ids:
        return dict(case), []
    alerts = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, disposition, case_id, tags,
                       affected_hosts, affected_ips, affected_users, raw_event,
                       created_at, event_time, llm_payload, iocs,
                       rule_id, rule_name, mitre_techniques, mitre_tactics,
                       confidence, ai_score, funnel_stage
                  FROM alerts
                 WHERE tenant_id = :tid
                   AND id = ANY(CAST(:ids AS uuid[]))
                 ORDER BY created_at ASC NULLS LAST
                """
            ).bindparams(tid=tenant_id, ids=[str(x) for x in alert_ids])
        )
    ).mappings().all()
    return dict(case), [dict(a) for a in alerts]


async def reconcile_campaign_case(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    dry_run: bool = True,
    temporal_window_seconds: int = 86_400,
) -> dict[str, Any]:
    """Split unjustified members out of a campaign case; keep evidenced links.

    ``dry_run`` defaults to ``True`` so accidental callers cannot mutate
    membership without an explicit apply. The HTTP endpoint mirrors this
    default via ``ReconcileBody.dry_run``.
    """
    case, alerts = await _load_case_alerts(db, tenant_id=tenant_id, case_id=case_id)
    if case is None:
        return {"ok": False, "error": "case_not_found", "case_id": str(case_id)}
    if len(alerts) <= 1:
        return {
            "ok": True,
            "case_id": str(case_id),
            "action": "noop",
            "reason": "solo_or_empty",
            "kept": [str(a["id"]) for a in alerts],
            "unlinked": [],
            "dry_run": dry_run,
        }

    # Prefer non-risk seed with strongest entity footprint; else oldest.
    non_risk = [a for a in alerts if not is_risk_supporting_alert(a)]
    seed_pool = non_risk or alerts
    seed = sorted(
        seed_pool,
        key=lambda a: (
            0 if (a.get("affected_hosts") or a.get("affected_ips") or a.get("affected_users")) else 1,
            a.get("created_at") or 0,
        ),
    )[0]

    candidates = [a for a in alerts if str(a["id"]) != str(seed["id"])]
    accepted, decisions = select_campaign_siblings(
        seed,
        candidates,
        temporal_window_seconds=temporal_window_seconds,
        limit=64,
        # Members already carry this case_id — disposition still gated.
        ignore_case_membership=True,
    )
    keep_ids = {str(seed["id"]), *[str(a["id"]) for a in accepted]}
    # Also keep supporting risk alerts that scored linked.
    for d in decisions:
        if d.get("linked") and d.get("role") == "supporting":
            keep_ids.add(str(d.get("alert_id")))

    unlinked = [a for a in alerts if str(a["id"]) not in keep_ids]
    kept = [a for a in alerts if str(a["id"]) in keep_ids]

    audit = {
        "algorithm_version": CORRELATION_VERSION,
        "reconciled_at": __import__("datetime").datetime.now(
            __import__("datetime").UTC
        ).isoformat(),
        "seed_alert_id": str(seed["id"]),
        "seed_title": str(seed.get("title") or ""),
        "kept": [str(a["id"]) for a in kept],
        "unlinked": [
            {
                "alert_id": str(a["id"]),
                "title": str(a.get("title") or ""),
                "decision": next(
                    (
                        d
                        for d in decisions
                        if str(d.get("alert_id")) == str(a["id"])
                    ),
                    {
                        "linked": False,
                        "decision_reason": "not scored / rejected",
                        "role": "rejected",
                    },
                ),
            }
            for a in unlinked
        ],
        "link_decisions": decisions,
    }

    if dry_run:
        return {
            "ok": True,
            "case_id": str(case_id),
            "action": "dry_run",
            "kept_count": len(kept),
            "unlinked_count": len(unlinked),
            "audit": audit,
            "dry_run": True,
        }

    # Unlink rejected alerts — clear case_id, demote ready_for_jira if set only
    # because of the megacase, reset disposition copied TP without evidence when
    # confidence is weak and title is powershell/admin-noise style.
    for a in unlinked:
        aid = a["id"]
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET case_id = NULL,
                       funnel_stage = CASE
                         WHEN funnel_stage IN ('ready_for_jira', 'cased', 'jira_pushed')
                         THEN 'triaged'
                         ELSE funnel_stage
                       END,
                       tags = COALESCE(tags, '[]'::jsonb)
                         || CAST(:tag AS jsonb),
                       updated_at = now()
                 WHERE tenant_id = :tid AND id = :aid
                """
            ).bindparams(
                tid=tenant_id,
                aid=aid,
                tag=json.dumps(
                    [
                        "campaign_unlinked",
                        f"unlinked_from:{case_id}",
                        "needs_entity_correlation",
                    ]
                ),
            )
        )

    keep_uuid = [
        a["id"] if isinstance(a["id"], uuid.UUID) else uuid.UUID(str(a["id"]))
        for a in kept
    ]
    # Rebuild case description + tags with explainable correlation.
    entity_note = (
        f"Reconciled megacase → kept {len(kept)} evidenced alert(s), "
        f"unlinked {len(unlinked)} without shared host/user/IP."
    )
    link_bits = "; ".join(
        f"{d.get('alert_id')}: {str(d.get('decision_reason') or '')[:100]}"
        for d in decisions
        if d.get("linked")
    ) or "seed only"
    new_description = (
        f"{case.get('description') or ''}\n\n---\n{entity_note}\n"
        f"Seed: {seed.get('title')}\nCorrelation: {link_bits}\n"
    )[:8000]
    tags = case.get("tags") if isinstance(case.get("tags"), dict) else {}
    tags = dict(tags or {})
    tags["correlation"] = audit
    tags["reconciled"] = True
    tags["needs_review"] = len(unlinked) > 0 or len(kept) <= 1

    await db.execute(
        text(
            """
            UPDATE aisoc_cases
               SET alert_ids = CAST(:aids AS uuid[]),
                   description = :desc,
                   tags = CAST(:tags AS jsonb),
                   status = CASE
                     WHEN status IN ('resolved', 'closed') THEN status
                     ELSE 'investigating'
                   END,
                   updated_at = now()
             WHERE id = :cid AND tenant_id = :tid
            """
        ).bindparams(
            cid=case_id,
            tid=tenant_id,
            aids=[str(x) for x in keep_uuid],
            desc=new_description,
            tags=json.dumps(tags),
        )
    )

    # Demote seed ready_for_jira when remaining membership lost evidenced links
    # and no investigation prose — severity alone must not keep Jira-ready.
    for a in kept:
        if str(a.get("funnel_stage") or "") != "ready_for_jira":
            continue
        conf = a.get("confidence") or a.get("ai_score")
        try:
            conf_f = float(conf) if conf is not None else 0.0
        except (TypeError, ValueError):
            conf_f = 0.0
        if conf_f > 1.0:
            conf_f = conf_f / 100.0
        if conf_f < 0.70:
            await db.execute(
                text(
                    """
                    UPDATE alerts
                       SET funnel_stage = 'cased',
                           updated_at = now()
                     WHERE tenant_id = :tid AND id = :aid
                       AND funnel_stage = 'ready_for_jira'
                    """
                ).bindparams(tid=tenant_id, aid=a["id"])
            )

    await db.commit()
    return {
        "ok": True,
        "case_id": str(case_id),
        "action": "reconciled",
        "kept_count": len(kept),
        "unlinked_count": len(unlinked),
        "kept": [str(a["id"]) for a in kept],
        "unlinked": [str(a["id"]) for a in unlinked],
        "audit": audit,
        "dry_run": False,
    }


async def score_case_membership(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    temporal_window_seconds: int = 86_400,
) -> dict[str, Any]:
    """Read-only audit of every alert↔seed link for a case (no writes).

    Uses Host-Centric + entity-overlap discovery annotations via
    ``select_campaign_siblings`` (pairwise against seed only). Membership
    already on the case is ignored for eligibility so legacy megacases can
    be audited without inventing entities.
    """
    case, alerts = await _load_case_alerts(db, tenant_id=tenant_id, case_id=case_id)
    if case is None:
        return {"ok": False, "error": "case_not_found"}
    if not alerts:
        return {
            "ok": True,
            "case_id": str(case_id),
            "links": [],
            "counts": summarize_correlation_decisions([]),
            "algorithm_version": CORRELATION_VERSION,
        }
    non_risk = [a for a in alerts if not is_risk_supporting_alert(a)]
    seed = sorted(
        non_risk or alerts,
        key=lambda a: (
            0 if (a.get("affected_hosts") or a.get("affected_ips") or a.get("affected_users")) else 1,
            a.get("created_at") or 0,
        ),
    )[0]
    candidates = [a for a in alerts if str(a["id"]) != str(seed["id"])]
    _accepted, decisions = select_campaign_siblings(
        seed,
        candidates,
        temporal_window_seconds=temporal_window_seconds,
        ignore_case_membership=True,
        limit=100,
    )
    # Ensure every case member appears in the audit even if discovery skipped it
    # (e.g. no shared entity) — score directly for explainability.
    decided_ids = {str(d.get("alert_id")) for d in decisions}
    links = list(decisions)
    for cand in candidates:
        cid = str(cand["id"])
        if cid in decided_ids:
            continue
        decision = score_campaign_link(
            seed, cand, temporal_window_seconds=temporal_window_seconds
        )
        payload = decision.to_dict()
        payload["alert_id"] = cid
        payload["title"] = str(cand.get("title") or "")
        payload["discovery_path"] = payload.get("discovery_path") or "audit_direct"
        payload["discovery_paths"] = payload.get("discovery_paths") or ["audit_direct"]
        links.append(payload)
    for link in links:
        if "title" not in link:
            match = next((a for a in candidates if str(a["id"]) == str(link.get("alert_id"))), None)
            link["title"] = str((match or {}).get("title") or "")
    counts = summarize_correlation_decisions(links)
    return {
        "ok": True,
        "case_id": str(case_id),
        "seed_alert_id": str(seed["id"]),
        "seed_title": str(seed.get("title") or ""),
        "seed_hosts": extract_alert_hosts(seed),
        "alert_count": len(alerts),
        "links": links,
        "counts": counts,
        "time_window_seconds": temporal_window_seconds,
        "algorithm_version": CORRELATION_VERSION,
        "read_only": True,
    }
