"""Evaluation report generator (Phase 8)."""

from __future__ import annotations

from typing import Any

from .contracts import AgenticCaseEvaluation, AgenticEvaluationReport, AgenticEvaluationRun


def build_report(
    run: AgenticEvaluationRun,
    cases: list[AgenticCaseEvaluation],
    metrics: dict[str, Any],
    gates: dict[str, Any],
    readiness: dict[str, Any],
) -> AgenticEvaluationReport:
    failures = [c.case_id for c in cases if c.analyst_review_required or c.agentic_result.pipeline_degraded]
    sections = {
        "dataset": {
            "datasetId": run.dataset_id,
            "datasetVersion": run.dataset_version,
            "totalCases": run.total_cases,
        },
        "methodology": "Deterministic metrics primary; LLM_AS_JUDGE not used for readiness.",
        "existing_soc_performance": {"score": metrics.get("existing_score"), "metrics": metrics},
        "agentic_soc_performance": {"score": metrics.get("agentic_score"), "metrics": metrics},
        "classification": {"mean": metrics.get("classification_mean")},
        "severity": {"mean": metrics.get("severity_mean")},
        "risk": {
            "mae": metrics.get("risk_mae"),
            "rmse": metrics.get("risk_rmse"),
            "calibration_error": metrics.get("risk_calibration_error"),
        },
        "evidence": {
            "support_rate": metrics.get("evidence_support_rate"),
            "hallucination_rate": metrics.get("hallucination_rate"),
        },
        "mitre": {"f1_mean": metrics.get("mitre_f1_mean")},
        "ioc": {"f1_mean": metrics.get("ioc_f1_mean")},
        "correlation": {"f1_mean": metrics.get("correlation_f1_mean")},
        "investigation": {"mean": metrics.get("investigation_mean")},
        "recommended_actions": {"dangerous_action_rate": metrics.get("dangerous_action_rate")},
        "cost": {
            "average_cost": metrics.get("average_cost"),
            "total_tokens": metrics.get("total_tokens"),
        },
        "latency": {"average_duration_ms": metrics.get("average_duration_ms")},
        "analyst_efficiency": metrics.get("analyst_efficiency"),
        "failures": failures,
        "comparison": {
            "existing": metrics.get("existing_score"),
            "agentic": metrics.get("agentic_score"),
            "delta": metrics.get("delta"),
        },
        "quality_gates": gates,
        "production_readiness": readiness,
        "versioning": {
            "agentVersion": run.agent_version,
            "workflowVersion": run.workflow_version,
            "promptVersion": run.prompt_version,
            "toolVersion": run.tool_version,
            "model": run.model,
            "datasetVersion": run.dataset_version,
        },
    }
    summary = (
        f"Evaluated {run.total_cases} cases on {run.dataset_id}: "
        f"agentic={metrics.get('agentic_score'):.2f} existing={metrics.get('existing_score'):.2f} "
        f"delta={metrics.get('delta'):+.2f}; readiness={readiness.get('status')}."
    )
    limitations = [
        "Synthetic golden cases labeled SYNTHETIC — not production ground truth.",
        "Analyst efficiency NOT_AVAILABLE unless operator timings supplied.",
        "Primary scoring is deterministic; LLM judge excluded from readiness.",
    ]
    if run.pipeline_status.get("degraded"):
        limitations.append("Pipeline ran with degraded adapters — see pipeline_status.")
    return AgenticEvaluationReport(
        evaluation_run_id=run.id,
        dataset_id=run.dataset_id,
        dataset_version=run.dataset_version,
        agent_version=run.agent_version,
        workflow_version=run.workflow_version,
        prompt_version=run.prompt_version,
        executive_summary=summary,
        sections=sections,
        limitations=limitations,
    )
