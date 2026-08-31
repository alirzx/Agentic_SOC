"""Stage-level pipeline metrics (Phase 8.5)."""

from __future__ import annotations

import time
from typing import Any

from app.runtime.contracts import AgentContext, AgentResult
from app.runtime.evidence import build_evidence_graph
from app.runtime.risk import RiskFactors, score_risk

REQUIRED_STAGES: tuple[str, ...] = (
    "triage",
    "investigation",
    "ti",
    "correlation",
    "evidence_graph",
    "risk",
    "decision",
    "report",
)

_AGENT_STAGE_MAP: dict[str, str] = {
    "triage": "triage",
    "investigation": "investigation",
    "threat-intel": "ti",
    "correlation": "correlation",
    "decision": "decision",
    "report": "report",
}


def _stage_status(result: AgentResult | None) -> str:
    if result is None:
        return "missing"
    if result.status == "success":
        return "completed"
    if result.status == "blocked":
        return "blocked"
    if result.status == "failed":
        return "failed"
    return str(result.status)


def build_stage_metrics(
    context: AgentContext,
    results: list[AgentResult],
    agent_order: list[str],
    *,
    stage_durations_ms: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Build per-stage success/duration metrics and pipeline completeness."""
    durations = stage_durations_ms or {}
    by_agent: dict[str, AgentResult] = {}
    for name, result in zip(agent_order, results, strict=False):
        by_agent[name] = result
    stages: dict[str, dict[str, Any]] = {}
    for agent_name, stage_key in _AGENT_STAGE_MAP.items():
        result = by_agent.get(agent_name)
        stages[stage_key] = {
            "status": _stage_status(result),
            "duration_ms": durations.get(stage_key, 0),
            "degraded": result is not None and result.status != "success",
            "error": result.reasoning if result and result.status == "failed" else None,
        }
    evidence_count = len(context.evidence)
    graph_ok = evidence_count > 0
    try:
        from app.runtime.evidence import build_evidence_graph

        findings: list[Any] = []
        for result in results:
            findings.extend(result.findings)
        graph = build_evidence_graph(findings=findings, evidence=context.evidence)
        graph_ok = bool(graph.nodes)
    except Exception:  # noqa: BLE001
        graph_ok = evidence_count > 0
    stages["evidence_graph"] = {
        "status": "completed" if graph_ok else "failed",
        "duration_ms": durations.get("evidence_graph", 0),
        "degraded": not graph_ok,
        "error": None if graph_ok else "no_evidence_graph",
        "evidence_count": evidence_count,
    }
    risk_ok = False
    risk_error: str | None = None
    try:
        factors = RiskFactors(
            alert_severity=str(context.state.severity or "medium"),
            correlation=min(10, evidence_count),
            attack_chain=min(15, len(context.previous_actions)),
        )
        assessment = score_risk(factors)
        risk_ok = assessment.score >= 0
        stages["risk"] = {
            "status": "completed",
            "duration_ms": durations.get("risk", 0),
            "degraded": False,
            "error": None,
            "score": assessment.score,
            "band": assessment.band,
        }
    except Exception as exc:  # noqa: BLE001
        risk_error = str(exc)
        stages["risk"] = {
            "status": "failed",
            "duration_ms": durations.get("risk", 0),
            "degraded": True,
            "error": risk_error,
        }
    completed = 0
    for key in REQUIRED_STAGES:
        row = stages.get(key, {})
        if row.get("status") == "completed":
            completed += 1
    completeness = completed / len(REQUIRED_STAGES)
    pipeline_degraded = completeness < 1.0
    return {
        "stages": stages,
        "triage_success": stages["triage"]["status"] == "completed",
        "investigation_success": stages["investigation"]["status"] == "completed",
        "ti_success": stages["ti"]["status"] == "completed",
        "correlation_success": stages["correlation"]["status"] == "completed",
        "risk_success": risk_ok,
        "decision_success": stages["decision"]["status"] == "completed",
        "report_success": stages["report"]["status"] == "completed",
        "completed_required_stages": completed,
        "total_required_stages": len(REQUIRED_STAGES),
        "pipeline_completeness": completeness,
        "pipeline_degraded": pipeline_degraded,
    }


class StageTimer:
    """Simple per-stage wall-clock timer for evaluation."""

    def __init__(self) -> None:
        self._starts: dict[str, float] = {}
        self._durations: dict[str, int] = {}

    def start(self, stage: str) -> None:
        self._starts[stage] = time.monotonic()

    def stop(self, stage: str) -> None:
        if stage not in self._starts:
            return
        elapsed = int((time.monotonic() - self._starts[stage]) * 1000)
        self._durations[stage] = self._durations.get(stage, 0) + elapsed
        del self._starts[stage]

    def as_dict(self) -> dict[str, int]:
        return dict(self._durations)
