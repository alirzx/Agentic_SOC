"""SLA metrics computation service.

Computes MTTD, MTTR, and MTTC from alert_sla_events,
compares against tenant-configured targets, and returns
per-severity SLA compliance summaries.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Text, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import get_settings
from app.models.alert import Alert
from app.models.sla import AlertSLAEvent, TenantSLAConfig
from app.models.tenant import Tenant

# 2026 published KPI bar defaults (tenants can override via ``settings.kpi_bar``).
DEFAULT_KPI_BAR_TARGETS: dict[str, float] = {
    "false_positive_rate_max_pct": 5.0,
    "alert_to_incident_ratio_min": 50.0,
    "mitre_technique_tagging_min_pct": 85.0,
    "mitre_subtechnique_tagging_min_pct": 60.0,
}

# Default per-severity SLA targets (minutes). These mirror the seed values
# in migrations 007 (critical/high/medium/low) and 040 (info) — `critical`
# carries the v1.5 P1 ≤15 min MTTD promise (W2 in the v1.5 SOC Console
# Parity plan), and `info` is the widest band because info-tier alerts
# are background context, not work items the analyst is on the clock for.
#
# Also used by the queue's `sla_due_at` expression as a catch-all for
# severities outside the standard ladder (`DEFAULT_SLA_TARGETS["info"]`).
DEFAULT_SLA_TARGETS: dict[str, dict[str, int]] = {
    "critical": {"mttd_target": 15, "mttr_target": 60, "mttc_target": 120},
    "high": {"mttd_target": 30, "mttr_target": 120, "mttc_target": 240},
    "medium": {"mttd_target": 60, "mttr_target": 240, "mttc_target": 480},
    "low": {"mttd_target": 120, "mttr_target": 480, "mttc_target": 1440},
    "info": {"mttd_target": 480, "mttr_target": 1440, "mttc_target": 2880},
}


def merge_kpi_bar_dict(existing: dict | None, patch: dict[str, float]) -> dict[str, float]:
    """Merge ``patch`` into stored ``kpi_bar`` and coerce to the four known keys + defaults."""
    kb = {**(existing or {}), **patch}
    out = {**DEFAULT_KPI_BAR_TARGETS}
    for k in DEFAULT_KPI_BAR_TARGETS:
        if k in kb:
            try:
                out[k] = float(kb[k])
            except (TypeError, ValueError):
                pass  # non-numeric value; skip key
    return out


def merge_tenant_settings_patch(existing: dict | None, patch: dict) -> dict:
    """Shallow-merge ``patch`` into tenant ``settings``; deep-merge only ``kpi_bar``."""
    out = dict(existing or {})
    for k, v in patch.items():
        if k == "kpi_bar" and isinstance(v, dict):
            prev = out.get("kpi_bar")
            base = prev if isinstance(prev, dict) else {}
            out["kpi_bar"] = merge_kpi_bar_dict(base, v)
        else:
            out[k] = v
    return out


async def load_kpi_bar_targets(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, float]:
    row = await db.execute(select(Tenant.settings).where(Tenant.id == tenant_id))
    raw = row.scalar_one_or_none() or {}
    kb = (raw or {}).get("kpi_bar") if isinstance((raw or {}).get("kpi_bar"), dict) else {}
    return merge_kpi_bar_dict(kb, {})


async def patch_tenant_kpi_bar_targets(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    patch: dict[str, float],
) -> dict[str, float]:
    """Persist merged KPI bar targets on the tenant row."""
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise ValueError("tenant not found")
    settings = dict(tenant.settings or {})
    prev_bar = settings.get("kpi_bar") if isinstance(settings.get("kpi_bar"), dict) else {}
    merged_bar = merge_kpi_bar_dict(prev_bar, patch)
    settings["kpi_bar"] = merged_bar
    tenant.settings = settings
    tenant.updated_at = datetime.now(UTC)
    flag_modified(tenant, "settings")
    await db.commit()
    return merged_bar


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _get_sla_configs(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, dict[str, int]]:
    """Return {severity: {mttd_target, mttr_target, mttc_target}} for the tenant."""
    rows = await db.execute(select(TenantSLAConfig).where(TenantSLAConfig.tenant_id == tenant_id))
    configs = rows.scalars().all()
    return {
        c.severity: {
            "mttd_target": c.mttd_target,
            "mttr_target": c.mttr_target,
            "mttc_target": c.mttc_target,
        }
        for c in configs
    }


async def _fetch_alert_events(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    since: datetime | None = None,
) -> dict[str, list[AlertSLAEvent]]:
    """Return events grouped by alert_id."""
    q = select(AlertSLAEvent).where(AlertSLAEvent.tenant_id == tenant_id)
    if since:
        q = q.where(AlertSLAEvent.occurred_at >= since)
    q = q.order_by(AlertSLAEvent.occurred_at)
    rows = await db.execute(q)
    events = rows.scalars().all()

    grouped: dict[str, list[AlertSLAEvent]] = {}
    for ev in events:
        key = str(ev.alert_id)
        grouped.setdefault(key, []).append(ev)
    return grouped


def _minutes_between(a: datetime | None, b: datetime | None) -> int | None:
    if a and b and b >= a:
        return int((b - a).total_seconds() / 60)
    return None


def _compute_durations(
    events: list[AlertSLAEvent],
) -> dict[str, Any]:
    """Compute MTTD/MTTR/MTTC in minutes for a single alert lifecycle."""
    by_type: dict[str, datetime] = {e.event_type: e.occurred_at for e in events}

    detected_at = by_type.get("detected")
    acknowledged_at = by_type.get("acknowledged")
    resolved_at = by_type.get("resolved")
    closed_at = by_type.get("closed")

    return {
        "alert_id": str(events[0].alert_id) if events else "",
        "mttd": _minutes_between(detected_at, acknowledged_at),
        "mttr": _minutes_between(detected_at, resolved_at),
        "mttc": _minutes_between(detected_at, closed_at),
        "severity": events[0].severity if events else "unknown",
        "source": "sla_events",
    }


def durations_from_alert(alert: Alert) -> dict[str, Any]:
    """Derive MTTD/MTTR/MTTC from alert timestamps when SLA events are missing.

    Mapping (existing columns → lifecycle):
      * detected     → ``first_seen`` / ``created_at`` / ``event_time``
      * acknowledged → ``first_seen_at`` or ``assigned_at``
      * resolved     → ``resolved_at`` when status is resolved / fp / false_positive
      * closed       → ``resolved_at`` (or ``updated_at``) when status is closed
    """
    detected = alert.first_seen or alert.created_at or alert.event_time
    acknowledged = alert.first_seen_at or alert.assigned_at
    status = (alert.status or "").strip().lower()
    resolved = alert.resolved_at if status in {"resolved", "fp", "false_positive"} else None
    closed = None
    if status == "closed":
        closed = alert.resolved_at or alert.updated_at
    elif status in {"fp", "false_positive"} and alert.resolved_at:
        # FP close counts toward MTTC when the alert was closed as noise.
        closed = alert.resolved_at
    sev = (alert.severity or "medium").strip().lower()
    if sev not in DEFAULT_SLA_TARGETS:
        sev = "medium"
    return {
        "alert_id": str(alert.id),
        "mttd": _minutes_between(detected, acknowledged),
        "mttr": _minutes_between(detected, resolved),
        "mttc": _minutes_between(detected, closed),
        "severity": sev,
        "source": "alert_timestamps",
    }


async def ensure_sla_event(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    severity: str,
    event_type: str,
    occurred_at: datetime | None = None,
    actor_id: uuid.UUID | None = None,
    metadata: dict | None = None,
) -> AlertSLAEvent | None:
    """Idempotently record one lifecycle event (no duplicate event_type per alert)."""
    if event_type not in {"detected", "acknowledged", "resolved", "closed"}:
        return None
    sev = (severity or "medium").strip().lower()
    if sev not in DEFAULT_SLA_TARGETS:
        sev = "medium"
    existing = await db.execute(
        select(AlertSLAEvent.id).where(
            AlertSLAEvent.tenant_id == tenant_id,
            AlertSLAEvent.alert_id == alert_id,
            AlertSLAEvent.event_type == event_type,
        ).limit(1)
    )
    if existing.scalar_one_or_none() is not None:
        return None
    event = AlertSLAEvent(
        tenant_id=tenant_id,
        alert_id=alert_id,
        severity=sev,
        event_type=event_type,
        occurred_at=occurred_at or datetime.now(UTC),
        actor_id=actor_id,
        metadata_=metadata or {},
    )
    db.add(event)
    return event


async def backfill_sla_events_from_alerts(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    days: int = 30,
    limit: int = 5000,
) -> dict[str, int]:
    """Materialize ``alert_sla_events`` from existing alert rows (idempotent)."""
    since = datetime.now(UTC) - timedelta(days=max(1, days))
    rows = await db.execute(
        select(Alert)
        .where(Alert.tenant_id == tenant_id, Alert.created_at >= since)
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    alerts = list(rows.scalars().all())
    written = {"detected": 0, "acknowledged": 0, "resolved": 0, "closed": 0, "alerts_scanned": len(alerts)}
    for alert in alerts:
        detected_at = alert.first_seen or alert.created_at or alert.event_time
        ev = await ensure_sla_event(
            db,
            tenant_id=tenant_id,
            alert_id=alert.id,
            severity=alert.severity,
            event_type="detected",
            occurred_at=detected_at,
            metadata={"source": "backfill"},
        )
        if ev:
            written["detected"] += 1
        ack_at = alert.first_seen_at or alert.assigned_at
        if ack_at:
            ev = await ensure_sla_event(
                db,
                tenant_id=tenant_id,
                alert_id=alert.id,
                severity=alert.severity,
                event_type="acknowledged",
                occurred_at=ack_at,
                metadata={"source": "backfill"},
            )
            if ev:
                written["acknowledged"] += 1
        status = (alert.status or "").strip().lower()
        if alert.resolved_at and status in {"resolved", "fp", "false_positive"}:
            ev = await ensure_sla_event(
                db,
                tenant_id=tenant_id,
                alert_id=alert.id,
                severity=alert.severity,
                event_type="resolved",
                occurred_at=alert.resolved_at,
                metadata={"source": "backfill", "status": status},
            )
            if ev:
                written["resolved"] += 1
        if status == "closed" or (status in {"fp", "false_positive"} and alert.resolved_at):
            closed_at = alert.resolved_at or alert.updated_at
            ev = await ensure_sla_event(
                db,
                tenant_id=tenant_id,
                alert_id=alert.id,
                severity=alert.severity,
                event_type="closed",
                occurred_at=closed_at,
                metadata={"source": "backfill", "status": status},
            )
            if ev:
                written["closed"] += 1
    await db.commit()
    return written


async def ensure_tenant_sla_config(db: AsyncSession, tenant_id: uuid.UUID) -> int:
    """Seed default per-severity targets when the tenant has none."""
    existing = await db.execute(select(TenantSLAConfig.severity).where(TenantSLAConfig.tenant_id == tenant_id))
    have = {row[0] for row in existing.all()}
    created = 0
    for sev, targets in DEFAULT_SLA_TARGETS.items():
        if sev in have:
            continue
        db.add(
            TenantSLAConfig(
                tenant_id=tenant_id,
                severity=sev,
                mttd_target=targets["mttd_target"],
                mttr_target=targets["mttr_target"],
                mttc_target=targets["mttc_target"],
            )
        )
        created += 1
    if created:
        await db.commit()
    return created


async def _compute_kpi_bar(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    since: datetime,
    targets: dict[str, float],
) -> dict[str, Any]:
    """Aggregate 2026 KPI bar metrics from ``alerts`` for the look-back window."""
    base = Alert.tenant_id == tenant_id, Alert.created_at >= since

    total_r = await db.execute(select(func.count()).select_from(Alert).where(*base))
    total = int(total_r.scalar_one() or 0)

    fp_r = await db.execute(select(func.count()).select_from(Alert).where(*base, Alert.status == "fp"))
    fp = int(fp_r.scalar_one() or 0)

    cases_r = await db.execute(select(func.count(func.distinct(Alert.case_id))).select_from(Alert).where(*base, Alert.case_id.is_not(None)))
    distinct_cases = int(cases_r.scalar_one() or 0)

    tagged_r = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(
            *base,
            func.coalesce(func.jsonb_array_length(Alert.mitre_techniques), 0) > 0,
        )
    )
    tagged = int(tagged_r.scalar_one() or 0)

    sub_r = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(
            *base,
            func.coalesce(func.jsonb_array_length(Alert.mitre_techniques), 0) > 0,
            Alert.mitre_techniques.cast(Text).like("%.%"),
        )
    )
    sub_tagged = int(sub_r.scalar_one() or 0)

    fp_rate_pct = round(fp / total * 100, 2) if total else 0.0
    if distinct_cases > 0:
        alert_to_incident = round(total / distinct_cases, 2)
    else:
        alert_to_incident = float(total) if total else 0.0

    mitre_tag_pct = round(tagged / total * 100, 2) if total else 0.0
    mitre_sub_pct = round(sub_tagged / total * 100, 2) if total else 0.0

    # Alert-to-incident: only evaluate when there is at least one incident;
    # alerts with zero linked cases are treated as meeting the ratio bar.
    breaches = {
        "false_positive_rate": fp_rate_pct > targets["false_positive_rate_max_pct"],
        "alert_to_incident_ratio": distinct_cases > 0 and alert_to_incident < targets["alert_to_incident_ratio_min"],
        "mitre_technique_tagging": mitre_tag_pct < targets["mitre_technique_tagging_min_pct"],
        "mitre_subtechnique_tagging": mitre_sub_pct < targets["mitre_subtechnique_tagging_min_pct"],
    }

    return {
        "targets": targets,
        "observed": {
            "total_alerts": total,
            "false_positives": fp,
            "false_positive_rate_pct": fp_rate_pct,
            "distinct_cases": distinct_cases,
            "alert_to_incident_ratio": alert_to_incident,
            "mitre_technique_tagging_pct": mitre_tag_pct,
            "mitre_subtechnique_tagging_pct": mitre_sub_pct,
        },
        "breaches": breaches,
        "breach_count": sum(1 for v in breaches.values() if v),
    }


def _avg_minutes(vals: list[int]) -> float | None:
    return round(sum(vals) / len(vals), 1) if vals else None


def _count_breaches(items: list[dict[str, Any]], targets: dict[str, Any]) -> int:
    return sum(
        1
        for i in items
        if (
            (i["mttd"] is not None and i["mttd"] > targets.get("mttd_target", 9999))
            or (i["mttr"] is not None and i["mttr"] > targets.get("mttr_target", 9999))
            or (i["mttc"] is not None and i["mttc"] > targets.get("mttc_target", 9999))
        )
    )


async def _durations_from_alerts(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    since: datetime,
) -> dict[str, dict[str, Any]]:
    """Fallback durations keyed by alert_id when ``alert_sla_events`` is empty/partial."""
    rows = await db.execute(
        select(Alert).where(Alert.tenant_id == tenant_id, Alert.created_at >= since)
    )
    out: dict[str, dict[str, Any]] = {}
    for alert in rows.scalars().all():
        out[str(alert.id)] = durations_from_alert(alert)
    return out


async def compute_sla_metrics(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    days: int = 30,
) -> dict[str, Any]:
    """Compute aggregated SLA metrics for the last N days.

    Prefer ``alert_sla_events`` when present; fill gaps from alert timestamps so
    the console is useful on tenants that never wrote the event table yet.
    """
    since = datetime.now(UTC) - timedelta(days=max(1, days))
    await ensure_tenant_sla_config(db, tenant_id)
    configs = await _get_sla_configs(db, tenant_id)
    grouped = await _fetch_alert_events(db, tenant_id, since=since)
    by_alert: dict[str, dict[str, Any]] = {}
    for alert_id, alert_events in grouped.items():
        by_alert[str(alert_id)] = _compute_durations(alert_events)
    # Merge alert-timestamp fallback for alerts missing from the event table.
    alert_fallback = await _durations_from_alerts(db, tenant_id, since)
    for alert_id, derived in alert_fallback.items():
        if alert_id not in by_alert:
            by_alert[alert_id] = derived
            continue
        existing = by_alert[alert_id]
        for key in ("mttd", "mttr", "mttc"):
            if existing.get(key) is None and derived.get(key) is not None:
                existing[key] = derived[key]
        if existing.get("severity") in (None, "unknown"):
            existing["severity"] = derived["severity"]

    buckets: dict[str, list[dict[str, Any]]] = {}
    for d in by_alert.values():
        sev = d.get("severity") or "medium"
        if sev not in DEFAULT_SLA_TARGETS:
            sev = "medium"
        buckets.setdefault(sev, []).append(d)

    per_severity: dict[str, dict[str, Any]] = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        items = buckets.get(sev, [])
        targets = configs.get(sev) or DEFAULT_SLA_TARGETS.get(sev, {})
        mttd_avg = _avg_minutes([i["mttd"] for i in items if i["mttd"] is not None])
        mttr_avg = _avg_minutes([i["mttr"] for i in items if i["mttr"] is not None])
        mttc_avg = _avg_minutes([i["mttc"] for i in items if i["mttc"] is not None])
        breaches = _count_breaches(items, targets)
        per_severity[sev] = {
            "total": len(items),
            "breaches": breaches,
            "breach_rate": round(breaches / len(items) * 100, 1) if items else 0.0,
            "mttd_avg": mttd_avg,
            "mttr_avg": mttr_avg,
            "mttc_avg": mttc_avg,
            "mttd_target": targets.get("mttd_target"),
            "mttr_target": targets.get("mttr_target"),
            "mttc_target": targets.get("mttc_target"),
        }

    all_items = [i for items in buckets.values() for i in items]
    all_mttd = [i["mttd"] for i in all_items if i["mttd"] is not None]
    all_mttr = [i["mttr"] for i in all_items if i["mttr"] is not None]
    all_mttc = [i["mttc"] for i in all_items if i["mttc"] is not None]
    total_breaches = sum(s["breaches"] for s in per_severity.values())
    total_alerts = sum(s["total"] for s in per_severity.values())
    overall = {
        "total_alerts": total_alerts,
        "total_breaches": total_breaches,
        "breach_rate": round(total_breaches / total_alerts * 100, 1) if total_alerts else 0.0,
        "mttd_avg": _avg_minutes(all_mttd),
        "mttr_avg": _avg_minutes(all_mttr),
        "mttc_avg": _avg_minutes(all_mttc),
        "with_mttd": len(all_mttd),
        "with_mttr": len(all_mttr),
        "with_mttc": len(all_mttc),
        "data_source": "hybrid_alerts_and_sla_events",
    }

    out: dict[str, Any] = {
        "period_days": days,
        "computed_at": datetime.now(UTC).isoformat(),
        "overall": overall,
        "per_severity": per_severity,
    }
    if get_settings().AISOC_FEATURE_KPI_BAR:
        kpi_targets = await load_kpi_bar_targets(db, tenant_id)
        out["kpi_bar"] = await _compute_kpi_bar(db, tenant_id, since, kpi_targets)
    else:
        out["kpi_bar"] = None
    return out
