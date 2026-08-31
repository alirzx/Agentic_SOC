"""Aggregate evaluation metrics (Phase 8)."""

from __future__ import annotations

from typing import Any

from ..contracts import AgenticCaseEvaluation
from ..benchmark_audit import audit_dataset
from .risk import calibration_error, mae, rmse


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def aggregate_case_evaluations(
    cases: list[AgenticCaseEvaluation],
    *,
    dataset_cases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not cases:
        return {}
    existing_overall = mean([_existing_overall(c) for c in cases])
    agentic_overall = mean([c.overall_score for c in cases])
    risk_errors = [
        abs((c.ground_truth.risk_score or 0) - c.agentic_result.risk_score)
        for c in cases
        if c.ground_truth.risk_score is not None
    ]
    gt_risks = [float(c.ground_truth.risk_score or 0) for c in cases if c.ground_truth.risk_score is not None]
    pred_risks = [c.agentic_result.risk_score for c in cases if c.ground_truth.risk_score is not None]
    evidence_rates = [c.metric_details.get("evidence_support_rate", c.evidence_score) for c in cases]
    unsupported = [c.metric_details.get("unsupported_claim_rate", 1 - c.hallucination_score) for c in cases]
    dangerous = [c.metric_details.get("dangerous_action_rate", 0.0) for c in cases]
    heuristic_scores = [
        float((c.metric_details.get("comparison_modes") or {}).get("heuristic_agentic") or 0.0)
        for c in cases
    ]
    llm_scores = [
        float((c.metric_details.get("comparison_modes") or {}).get("llm_agentic") or 0.0)
        for c in cases
        if (c.metric_details.get("comparison_modes") or {}).get("llm_agentic") is not None
    ]
    audit = audit_dataset(dataset_cases or [])
    existing_valid = audit.get("existing_score_valid", False)
    substrate_self_consistency = existing_overall if not existing_valid else None
    delta_valid = None
    if existing_valid:
        delta_valid = agentic_overall - existing_overall
    elif heuristic_scores:
        delta_valid = agentic_overall - mean(heuristic_scores)
    return {
        "cases": len(cases),
        "accuracy": agentic_overall,
        "classification_mean": mean([c.classification_score for c in cases]),
        "severity_mean": mean([c.severity_score for c in cases]),
        "risk_mae": mae(risk_errors),
        "risk_rmse": rmse(risk_errors),
        "risk_calibration_error": calibration_error(pred_risks, gt_risks),
        "mitre_f1_mean": mean([c.mitre_score for c in cases]),
        "ioc_f1_mean": mean([c.ioc_score for c in cases]),
        "correlation_f1_mean": mean([c.correlation_score for c in cases]),
        "evidence_support_rate": mean([float(r) for r in evidence_rates]),
        "hallucination_rate": mean([float(u) for u in unsupported]),
        "investigation_mean": mean([c.investigation_score for c in cases]),
        "action_mean": mean([c.action_score for c in cases]),
        "average_duration_ms": mean([float(c.agentic_result.duration_ms) for c in cases]),
        "avg_duration_ms": mean([float(c.agentic_result.duration_ms) for c in cases]),
        "average_cost": mean([c.agentic_result.estimated_cost for c in cases]),
        "cost_per_case": mean([c.agentic_result.estimated_cost for c in cases]),
        "pipeline_completeness_mean": mean(
            [float(c.stage_metrics.get("pipeline_completeness", 0)) for c in cases if c.stage_metrics]
        ) if any(c.stage_metrics for c in cases) else 0.0,
        "total_tokens": sum(c.agentic_result.input_tokens + c.agentic_result.output_tokens for c in cases),
        "dangerous_action_rate": mean([float(d) for d in dangerous]),
        "production_action_leakage": 0.0,
        "analyst_efficiency": "NOT_AVAILABLE",
        "existing_score": existing_overall,
        "existing_score_valid": existing_valid,
        "substrate_self_consistency_score": substrate_self_consistency,
        "heuristic_agentic_score": mean(heuristic_scores) if heuristic_scores else None,
        "llm_agentic_score": mean(llm_scores) if llm_scores else None,
        "agentic_score": agentic_overall,
        "delta": agentic_overall - existing_overall,
        "delta_valid_for_optimization": delta_valid,
        "delta_valid_baseline": "existing_substrate_proxy" if existing_valid else "heuristic_agentic",
        "benchmark_audit": audit,
    }


def _existing_overall(case: AgenticCaseEvaluation) -> float:
    details = case.metric_details.get("existing_scores") or {}
    if details:
        return float(details.get("overall", 0.0))
    return mean(
        [
            case.metric_details.get("existing_classification", 0.0),
            case.metric_details.get("existing_severity", 0.0),
            case.metric_details.get("existing_mitre_f1", 0.0),
        ]
    )
