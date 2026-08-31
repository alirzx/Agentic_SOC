"""Failure taxonomy for evaluation cases (Phase 8.5 / 8.6)."""

from __future__ import annotations

from typing import Any, Literal

FailureCategory = Literal[
    "MISSING_DATA",
    "BAD_TOOL",
    "TOOL_PERMISSION",
    "RETRIEVAL_FAILURE",
    "CORRELATION_FAILURE",
    "EVIDENCE_FAILURE",
    "HEURISTIC",
    "LLM_REASONING",
    "TOOL",
    "RETRIEVAL",
    "EVIDENCE",
    "CORRELATION",
    "SCORING",
    "MODEL",
    "PROMPT",
    "INFRASTRUCTURE",
    "REASONING_FAILURE",
    "HALLUCINATION",
    "PROMPT_FAILURE",
    "MODEL_FAILURE",
    "STRUCTURED_OUTPUT_REPAIR_FAILED",
    "STRUCTURED_OUTPUT_PARSE_ERROR",
    "SCHEMA_VALIDATION_ERROR",
    "LLM_AUTH_FAILURE",
    "LLM_PROVIDER_FAILURE",
    "TIMEOUT",
    "COST_BUDGET",
]


def classify_failures(
    *,
    case_payload: dict[str, Any],
    stage_metrics: dict[str, Any],
    metric_details: dict[str, Any],
    agentic_degraded: bool,
    orchestrator_error: str | None = None,
    execution_mode: str = "UNKNOWN",
) -> list[str]:
    """Assign one or more failure categories to a case."""
    categories: list[str] = []
    if orchestrator_error:
        if "timeout" in orchestrator_error.lower():
            categories.append("TIMEOUT")
        else:
            categories.append("INFRASTRUCTURE")
    stages = stage_metrics.get("stages") or {}
    if stages.get("ti", {}).get("status") != "completed":
        categories.append("RETRIEVAL_FAILURE")
    if stages.get("correlation", {}).get("status") != "completed":
        categories.append("CORRELATION_FAILURE")
    if stages.get("evidence_graph", {}).get("status") != "completed":
        categories.append("EVIDENCE_FAILURE")
    if metric_details.get("unsupported_claim_rate", 0) > 0.05:
        categories.append("HALLUCINATION")
    if metric_details.get("dangerous_action_rate", 0) > 0:
        categories.append("BAD_TOOL")
    if metric_details.get("production_action_leakage", 0) > 0:
        categories.append("TOOL_PERMISSION")
    if not case_payload.get("telemetry") and not case_payload.get("description"):
        categories.append("MISSING_DATA")
    if execution_mode == "FALLBACK_HEURISTIC":
        categories.append("HEURISTIC")
        fallback_reason = metric_details.get("fallback_reason") or ""
        if metric_details.get("llm_error"):
            categories.append("MODEL_FAILURE")
        if fallback_reason in {
            "STRUCTURED_OUTPUT_REPAIR_FAILED",
            "STRUCTURED_OUTPUT_PARSE_ERROR",
            "SCHEMA_VALIDATION_ERROR",
        }:
            categories.append("PROMPT_FAILURE")
        if fallback_reason in {"LLM_AUTH_FAILURE", "INVALID_API_KEY", "LLM_RATE_LIMIT", "LLM_TIMEOUT"}:
            categories.append("LLM_PROVIDER_FAILURE")
    elif execution_mode == "LLM":
        if metric_details.get("classification", {}).get("agentic", 1) < 0.25:
            categories.append("LLM_REASONING")
    elif execution_mode == "HEURISTIC":
        categories.append("HEURISTIC")
    if agentic_degraded and stage_metrics.get("pipeline_degraded"):
        if "INFRASTRUCTURE" not in categories:
            categories.append("INFRASTRUCTURE")
    tool_errors = metric_details.get("tool_errors") or []
    if tool_errors:
        categories.append("TOOL")
    return list(dict.fromkeys(categories))
