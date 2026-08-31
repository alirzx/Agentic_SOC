"""Aggregate evaluation metrics (Phase 8)."""

from __future__ import annotations

from typing import Any

from ..contracts import AgenticCaseEvaluation
from .risk import calibration_error, mae, rmse


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def aggregate_case_evaluations(cases: list[AgenticCaseEvaluation]) -> dict[str, Any]:
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
        "average_cost": mean([c.agentic_result.estimated_cost for c in cases]),
        "total_tokens": sum(c.agentic_result.input_tokens + c.agentic_result.output_tokens for c in cases),
        "dangerous_action_rate": mean([float(d) for d in dangerous]),
        "production_action_leakage": 0.0,
        "analyst_efficiency": "NOT_AVAILABLE",
        "existing_score": existing_overall,
        "agentic_score": agentic_overall,
        "delta": agentic_overall - existing_overall,
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
