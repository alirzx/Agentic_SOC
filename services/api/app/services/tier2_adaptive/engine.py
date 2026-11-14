"""Tier-2 Adaptive Investigation Engine orchestrator.

Selected when ``AISOC_TIER2_ADAPTIVE`` is enabled. Legacy IP-pivot remains the
default path. Shadow mode evaluates adaptive without mutating cases.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.tier2_adaptive.case_policy import (
    CaseDecision,
    apply_case_decision,
    decide_case_action,
)
from app.services.tier2_adaptive.correlation import (
    CorrelationHistoryEntry,
    correlate_candidates,
    find_related_alerts_entity_aware,
)
from app.services.tier2_adaptive.entities import (
    EntityExtractionResult,
    extract_alert_entities,
)
from app.services.tier2_adaptive.feature_flags import selected_tier2_path
from app.services.tier2_adaptive.investigation import (
    InvestigationReport,
    execute_adaptive_investigation,
)
from app.services.tier2_adaptive.profiles import ProfileSelection, select_investigation_profiles

logger = structlog.get_logger()

# Eight-stage adaptive runbook (P6 UI). Legacy five-step names kept as aliases.
TIER2_ADAPTIVE_STEPS: tuple[dict[str, str], ...] = (
    {"action_name": "tier2_alert_context", "label": "1. Alert Context"},
    {"action_name": "tier2_entity_extraction", "label": "2. Entity Extraction"},
    {"action_name": "tier2_domain_classification", "label": "3. Domain Classification"},
    {"action_name": "tier2_related_discovery", "label": "4. Related Alert Discovery"},
    {"action_name": "tier2_correlation_analysis", "label": "5. Correlation Analysis"},
    {"action_name": "tier2_case_management", "label": "6. Case Management"},
    {"action_name": "tier2_investigation", "label": "7. Investigation"},
    {"action_name": "tier2_final_report", "label": "8. Final Report"},
)

# Backward-compatible aliases so older UI/API clients still resolve.
LEGACY_STEP_ALIASES: dict[str, str] = {
    "tier2_extract_ips": "tier2_entity_extraction",
    "tier2_find_related": "tier2_related_discovery",
    "tier2_aggregate_case": "tier2_case_management",
    "tier2_investigate": "tier2_investigation",
    "tier2_case_report": "tier2_final_report",
}


@dataclass
class AdaptivePivotResult:
    entities: EntityExtractionResult
    profiles: ProfileSelection
    correlation: CorrelationHistoryEntry
    case_decision: CaseDecision
    report: InvestigationReport
    related_alert_ids: list[str] = field(default_factory=list)
    case_id: str | None = None
    case_created: bool = False
    case_extended: bool = False
    window_hours: int = 24
    notes: list[str] = field(default_factory=list)
    execution_path: str = "adaptive"

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_path": self.execution_path,
            "entities": self.entities.to_dict(),
            "profiles": self.profiles.to_dict(),
            "correlation": self.correlation.to_dict(),
            "case_decision": self.case_decision.to_dict(),
            "report": self.report.to_dict(),
            "related_alert_ids": self.related_alert_ids,
            "case_id": self.case_id,
            "case_created": self.case_created,
            "case_extended": self.case_extended,
            "window_hours": self.window_hours,
            "notes": self.notes,
            "related_count": max(0, len(self.related_alert_ids) - 1),
            # Legacy IP fields for API compatibility.
            "src_ips": self.entities.values("ip")[:8],
            "dest_ips": self.entities.values("ip")[:8],
        }


def _alert_as_dict(alert: Any) -> dict[str, Any]:
    if isinstance(alert, dict):
        return dict(alert)
    out: dict[str, Any] = {}
    for name in dir(alert):
        if name.startswith("_"):
            continue
        if name in {
            "id",
            "title",
            "severity",
            "disposition",
            "status",
            "case_id",
            "tenant_id",
            "rule_name",
            "rule_id",
            "security_domain",
            "detection_type",
            "mitre_techniques",
            "affected_hosts",
            "affected_ips",
            "affected_users",
            "llm_payload",
            "raw_event",
            "enrichment_data",
            "iocs",
            "annotations",
            "entity",
            "event_time",
            "created_at",
        }:
            try:
                out[name] = getattr(alert, name)
            except Exception:  # noqa: BLE001
                continue
    return out


def run_adaptive_pipeline_sync(
    alert: Any,
    *,
    related_candidates: list[dict[str, Any]] | None = None,
    hours: int = 24,
    shadow: bool = False,
    unavailable_tools: set[str] | None = None,
) -> AdaptivePivotResult:
    """Pure synchronous pipeline (no DB) — used by unit tests and shadow eval."""
    row = _alert_as_dict(alert)
    notes: list[str] = []
    entities = extract_alert_entities(row)
    notes.append(f"Extracted {len(entities.entities)} entity observation(s)")
    profiles = select_investigation_profiles(row, entities=entities)
    notes.append(f"Profiles: {', '.join(profiles.names)}")

    candidates = related_candidates or []
    correlation = correlate_candidates(
        row,
        candidates,
        seed_entities=entities,
        temporal_window_seconds=hours * 3600,
        min_decision="unrelated",
    )
    related_ids = [str(row.get("id") or row.get("alert_id") or "")]
    related_alerts = [row]
    for result in correlation.results:
        if result.decision in {"candidate", "eligible"}:
            related_ids.append(result.candidate_alert_id)
            match = next(
                (
                    c
                    for c in candidates
                    if str(c.get("id") or c.get("alert_id")) == result.candidate_alert_id
                ),
                {"id": result.candidate_alert_id},
            )
            related_alerts.append(match)

    decision = decide_case_action(row, entities=entities, correlation=correlation)
    if shadow:
        notes.append("shadow_mode: case mutations skipped")
        # Force non-mutating decision copy
        decision = CaseDecision(
            action=decision.action if decision.action in {"standalone", "review"} else "review",
            reason=f"shadow:{decision.reason}",
            case_id=decision.case_id,
            correlation_score=decision.correlation_score,
            entity_snapshot=decision.entity_snapshot,
            idempotency_key=f"shadow:{decision.idempotency_key}",
        )

    steps, report = execute_adaptive_investigation(
        alert=row,
        entities=entities,
        profiles=profiles,
        correlation=correlation,
        case_decision=decision,
        related_alerts=related_alerts,
        unavailable_tools=unavailable_tools,
    )
    _ = steps
    return AdaptivePivotResult(
        entities=entities,
        profiles=profiles,
        correlation=correlation,
        case_decision=decision,
        report=report,
        related_alert_ids=list(dict.fromkeys(related_ids)),
        case_id=decision.case_id,
        case_created=decision.action == "create" and not shadow,
        case_extended=decision.action == "extend" and not shadow,
        window_hours=hours,
        notes=notes,
        execution_path=selected_tier2_path(),
    )


async def run_adaptive_investigate_preflight(
    db: AsyncSession,
    *,
    alert: Any,
    tenant_id: uuid.UUID,
    hours: int = 24,
    investigate_queued: bool = True,
    shadow: bool = False,
) -> tuple[AdaptivePivotResult, list[dict[str, Any]]]:
    """Full adaptive preflight — never exits early for missing IPs."""
    from app.services.tier2_ip_pivot import persist_tier2_snapshot

    row = _alert_as_dict(alert)
    row["tenant_id"] = str(tenant_id)
    alert_id = alert.id if hasattr(alert, "id") else uuid.UUID(str(row.get("id")))
    row["id"] = str(alert_id)
    run_token = uuid.uuid4().hex[:12]
    path = selected_tier2_path()
    logger.info("tier2.adaptive.start", alert_id=str(alert_id), path=path, shadow=shadow)

    entities = extract_alert_entities(row)
    profiles = select_investigation_profiles(row, entities=entities)

    related_rows, correlation = await find_related_alerts_entity_aware(
        db,
        tenant_id=tenant_id,
        seed=row,
        seed_entities=entities,
        hours=hours,
    )
    # related_rows[0] is seed
    related_summaries = [
        {
            "id": str(r.get("id")),
            "title": r.get("title"),
            "severity": r.get("severity"),
            "disposition": r.get("disposition"),
            "status": r.get("status"),
        }
        for r in related_rows
    ]

    decision = decide_case_action(
        row,
        entities=entities,
        correlation=correlation,
        existing_case_id=str(row["case_id"]) if row.get("case_id") else None,
    )

    case_created = False
    case_extended = False
    case_id = decision.case_id
    if not shadow and decision.action in {"create", "extend"}:
        related_uuids = []
        for r in related_rows[1:]:
            try:
                related_uuids.append(uuid.UUID(str(r["id"])))
            except (ValueError, KeyError):
                continue
        # Only auto-extend membership for eligible correlations.
        eligible_ids = [
            uuid.UUID(r.candidate_alert_id)
            for r in correlation.results
            if r.decision == "eligible"
        ]
        applied, _membership = await apply_case_decision(
            db,
            tenant_id=tenant_id,
            alert=row,
            decision=decision,
            related_alert_ids=eligible_ids or None,
            entities=entities,
        )
        decision = applied
        case_id = applied.case_id
        case_created = applied.action == "create"
        case_extended = applied.action == "extend"
        await db.commit()
    elif shadow:
        decision = CaseDecision(
            action="review" if decision.action in {"create", "extend"} else decision.action,
            reason=f"shadow:{decision.reason}",
            case_id=decision.case_id,
            correlation_score=decision.correlation_score,
            entity_snapshot=decision.entity_snapshot,
            idempotency_key=f"shadow:{decision.idempotency_key}",
        )

    steps, report = execute_adaptive_investigation(
        alert=row,
        entities=entities,
        profiles=profiles,
        correlation=correlation,
        case_decision=decision,
        related_alerts=related_rows,
    )

    result = AdaptivePivotResult(
        entities=entities,
        profiles=profiles,
        correlation=correlation,
        case_decision=decision,
        report=report,
        related_alert_ids=[str(r.get("id")) for r in related_rows],
        case_id=case_id,
        case_created=case_created,
        case_extended=case_extended,
        window_hours=hours,
        notes=[
            f"path={path}",
            f"entities={len(entities.entities)}",
            f"profiles={','.join(profiles.names)}",
            f"case={decision.action}",
        ],
        execution_path=path,
    )

    runbook_steps = _build_runbook_steps(
        result=result,
        investigate_queued=investigate_queued,
        steps_detail=steps,
    )
    try:
        await persist_tier2_snapshot(
            db,
            tenant_id=tenant_id,
            alert_id=alert_id,
            steps=runbook_steps,
            pivot={
                "adaptive": True,
                "execution_path": path,
                "related_alert_ids": result.related_alert_ids,
                "case_id": case_id,
                "run_token": run_token,
                "profiles": profiles.names,
                "case_decision": decision.to_dict(),
                "report": report.to_dict(),
                "entities_count": len(entities.entities),
            },
        )
        # Also store adaptive payload under enrichment for UI.
        await _persist_adaptive_enrichment(
            db,
            tenant_id=tenant_id,
            alert_id=alert_id,
            result=result,
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        logger.warning("tier2.adaptive.persist_failed", error_type=type(exc).__name__)

    logger.info(
        "tier2.adaptive.done",
        alert_id=str(alert_id),
        profiles=profiles.names,
        case_action=decision.action,
        related=len(result.related_alert_ids),
    )
    return result, related_summaries


def _build_runbook_steps(
    *,
    result: AdaptivePivotResult,
    investigate_queued: bool,
    steps_detail: list[Any],
) -> list[dict[str, Any]]:
    ents = result.entities
    profiles = result.profiles
    corr = result.correlation
    decision = result.case_decision
    report = result.report

    def _status_from_presence(ok: bool, empty_label: str) -> tuple[str, str]:
        if ok:
            return "executed", empty_label
        return "skipped", empty_label

    entity_summary = (
        f"Extracted {len(ents.entities)} entities across "
        f"{len(ents.counts_by_type())} types"
        if ents.entities
        else "No entities extracted — continuing with evidence-only investigation"
    )
    # Missing IP is NOT an error.
    if not ents.values("ip"):
        entity_summary += " (no IP — not blocking)"

    corr_eligible = [r for r in corr.results if r.decision == "eligible"]
    corr_cand = [r for r in corr.results if r.decision == "candidate"]

    invest_status = "executed"
    invest_summary = (
        f"Ran {len(steps_detail)} profile steps; "
        f"assessment={report.final_assessment}"
    )
    if investigate_queued:
        invest_summary += " · Investigate queued"

    return [
        {
            "action_name": "tier2_alert_context",
            "label": TIER2_ADAPTIVE_STEPS[0]["label"],
            "status": "executed",
            "summary": (
                f"{report.alert_summary.get('title') or 'Alert'} · "
                f"severity={report.alert_summary.get('severity')}"
            ),
            "detail": json.dumps(report.alert_summary, default=str)[:2000],
        },
        {
            "action_name": "tier2_entity_extraction",
            "label": TIER2_ADAPTIVE_STEPS[1]["label"],
            "status": "executed",
            "summary": entity_summary,
            "detail": json.dumps(ents.counts_by_type())[:2000],
        },
        {
            "action_name": "tier2_domain_classification",
            "label": TIER2_ADAPTIVE_STEPS[2]["label"],
            "status": "executed",
            "summary": f"Profiles: {', '.join(profiles.names)}",
            "detail": json.dumps(profiles.to_dict(), default=str)[:2000],
        },
        {
            "action_name": "tier2_related_discovery",
            "label": TIER2_ADAPTIVE_STEPS[3]["label"],
            "status": "executed" if len(result.related_alert_ids) > 1 else "executed",
            "summary": (
                f"Related alerts: {max(0, len(result.related_alert_ids) - 1)} "
                f"(window {result.window_hours}h)"
            ),
            "detail": None,
        },
        {
            "action_name": "tier2_correlation_analysis",
            "label": TIER2_ADAPTIVE_STEPS[4]["label"],
            "status": "executed",
            "summary": (
                f"eligible={len(corr_eligible)} candidate={len(corr_cand)} "
                f"scored={len(corr.results)}"
            ),
            "detail": json.dumps(
                [r.to_dict() for r in corr.results[:8]], default=str
            )[:3000],
        },
        {
            "action_name": "tier2_case_management",
            "label": TIER2_ADAPTIVE_STEPS[5]["label"],
            "status": "executed",
            "summary": f"Decision: {decision.action} — {decision.reason}",
            "detail": json.dumps(decision.to_dict(), default=str)[:2000],
        },
        {
            "action_name": "tier2_investigation",
            "label": TIER2_ADAPTIVE_STEPS[6]["label"],
            "status": invest_status,
            "summary": invest_summary,
            "detail": json.dumps(
                [s.to_dict() for s in steps_detail[:12]], default=str
            )[:3000],
        },
        {
            "action_name": "tier2_final_report",
            "label": TIER2_ADAPTIVE_STEPS[7]["label"],
            "status": "executed",
            "summary": (
                f"{report.report_kind} report · {report.final_assessment} · "
                f"confidence={report.confidence}"
            ),
            "detail": json.dumps(
                {
                    "findings": report.findings[:6],
                    "limitations": report.limitations[:6],
                    "recommendations": report.recommendations[:6],
                },
                default=str,
            )[:3000],
        },
    ]


async def _persist_adaptive_enrichment(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    result: AdaptivePivotResult,
) -> None:
    from sqlalchemy import text

    payload = {
        "tier2_adaptive": {
            "ran_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "execution_path": result.execution_path,
            "profiles": result.profiles.names,
            "case_decision": result.case_decision.to_dict(),
            "report": result.report.to_dict(),
            "entity_counts": result.entities.counts_by_type(),
            "correlation": result.correlation.to_dict(),
        }
    }
    await db.execute(
        text(
            """
            UPDATE alerts
               SET enrichment_data = COALESCE(enrichment_data, '{}'::jsonb)
                                   || CAST(:payload AS JSONB),
                   updated_at = NOW()
             WHERE id = :id AND tenant_id = :tid
            """
        ).bindparams(
            id=alert_id,
            tid=tenant_id,
            payload=json.dumps(payload),
        )
    )


def adaptive_step_catalog() -> list[dict[str, str]]:
    return [dict(item) for item in TIER2_ADAPTIVE_STEPS]
