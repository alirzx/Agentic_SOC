"""Extract normalized SOC snapshots from orchestrator output (Phase 8)."""

from __future__ import annotations

import re
from typing import Any

from app.runtime.contracts import AgentContext, AgentResult, Evidence, Finding

from .contracts import SocResultSnapshot
from .scoring.investigation import INVESTIGATION_STAGES, STAGE_KEYWORDS


def _extract_iocs_from_evidence(evidence: list[Evidence]) -> list[str]:
    iocs: list[str] = []
    for item in evidence:
        data = item.data or {}
        for key in ("ioc", "ip", "src_ip", "domain", "hash", "value"):
            val = data.get(key)
            if val:
                iocs.append(str(val))
    return iocs


def _mitre_from_results(results: list[AgentResult]) -> list[str]:
    techniques: list[str] = []
    for result in results:
        for finding in result.findings:
            techniques.extend(finding.mitre_techniques)
    return list(dict.fromkeys(techniques))


def _claims_from_results(results: list[AgentResult]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for result in results:
        for finding in result.findings:
            claims.append(
                {
                    "claim": finding.statement,
                    "evidence_ids": list(finding.evidence_ids),
                    "confidence": finding.confidence,
                }
            )
    return claims


def _investigation_stages(context: AgentContext, results: list[AgentResult]) -> dict[str, bool]:
    blob = (context.objective or "") + " " + str(context.state.raw_alert)
    for result in results:
        blob += " " + (result.reasoning or "")
    lowered = blob.lower()
    stages: dict[str, bool] = {}
    for stage, keywords in STAGE_KEYWORDS.items():
        stages[stage] = any(kw in lowered for kw in keywords)
    return stages


def _parse_risk_from_results(results: list[AgentResult]) -> tuple[float, str]:
    for result in results:
        for finding in result.findings:
            if "risk=" in finding.statement:
                match = re.search(r"risk=(\d+(?:\.\d+)?)/(\w+)", finding.statement)
                if match:
                    return float(match.group(1)), match.group(2)
    return float(context_risk_fallback(results)), ""


def context_risk_fallback(results: list[AgentResult]) -> float:
    for result in reversed(results):
        if result.confidence:
            return result.confidence * 100
    return 0.0


def snapshot_from_orchestrator(
    context: AgentContext,
    results: list[AgentResult],
    *,
    duration_ms: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    estimated_cost: float = 0.0,
    tool_call_count: int = 0,
    degraded_agents: list[str] | None = None,
) -> SocResultSnapshot:
    degraded = degraded_agents or []
    evidence_dicts = [e.model_dump(mode="json") for e in context.evidence]
    risk_score, risk_band = _parse_risk_from_results(results)
    actions: list[str] = []
    for result in results:
        actions.extend(a.name for a in result.actions)
    classification = ""
    for result in results:
        for finding in result.findings:
            if finding.statement.startswith("decision="):
                classification = finding.statement
    return SocResultSnapshot(
        classification=classification,
        severity=str(context.state.severity or ""),
        risk_score=risk_score,
        risk_band=risk_band,
        confidence=float(context.state.confidence or 0.0),
        affected_assets=[str(context.state.raw_alert.get("hostname") or "")] if context.state.raw_alert.get("hostname") else [],
        affected_users=[str(context.state.raw_alert.get("username") or "")] if context.state.raw_alert.get("username") else [],
        iocs=_extract_iocs_from_evidence(context.evidence),
        mitre_techniques=_mitre_from_results(results),
        recommended_actions=list(dict.fromkeys(actions)),
        correlation_groups=[[context.incident_id]],
        evidence=evidence_dicts,
        claims=_claims_from_results(results),
        investigation_stages=_investigation_stages(context, results),
        duration_ms=duration_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        estimated_cost=estimated_cost,
        tool_call_count=tool_call_count,
        pipeline_degraded=bool(degraded),
        degraded_agents=degraded,
    )


def existing_snapshot_from_case(case: dict[str, Any]) -> SocResultSnapshot:
    """Deterministic existing-SOC proxy from substrate / fusion fields."""
    iocs: list[str] = []
    for key in ("src_ip", "domain", "file_hash"):
        if case.get(key):
            iocs.append(str(case[key]))
    for row in case.get("telemetry") or []:
        if isinstance(row, dict):
            for key in ("ClientIP", "src_ip", "IpAddress"):
                if row.get(key):
                    iocs.append(str(row[key]))
    return SocResultSnapshot(
        classification=str(case.get("response_class") or case.get("fusion_decision") or ""),
        severity=str(case.get("severity") or "medium"),
        risk_score=float(case.get("risk_score") or 0) if case.get("risk_score") is not None else 0.0,
        confidence=0.5,
        mitre_techniques=list(case.get("expected_techniques") or []),
        iocs=list(dict.fromkeys(iocs)),
        recommended_actions=[str(case.get("response_class") or "")] if case.get("response_class") else [],
    )
