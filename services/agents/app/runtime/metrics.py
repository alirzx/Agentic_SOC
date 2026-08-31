"""Prometheus + in-process metrics for shadow runs (Phase 7)."""

from __future__ import annotations

from typing import Any

_COUNTS: dict[str, int] = {
    "runs": 0,
    "success": 0,
    "failed": 0,
    "timeout": 0,
    "queued": 0,
}

try:
    from prometheus_client import Counter, Histogram

    RUNS = Counter("agentic_shadow_runs_total", "Shadow runs started")
    SUCCESS = Counter("agentic_shadow_success_total", "Shadow runs completed")
    FAILED = Counter("agentic_shadow_failed_total", "Shadow runs failed")
    TIMEOUT = Counter("agentic_shadow_timeout_total", "Shadow runs timed out")
    DURATION = Histogram("agentic_shadow_duration_ms", "Shadow run duration (ms)")
    TOOL_CALLS = Histogram("agentic_shadow_tool_calls", "Tool calls per shadow run")
    INPUT_TOKENS = Histogram("agentic_shadow_input_tokens", "Input tokens per shadow run")
    OUTPUT_TOKENS = Histogram("agentic_shadow_output_tokens", "Output tokens per shadow run")
    RISK = Histogram("agentic_shadow_risk_score", "Shadow run risk score")
    CONFIDENCE = Histogram("agentic_shadow_confidence", "Shadow run confidence")
except Exception:  # noqa: BLE001 — metrics must never break the worker
    RUNS = SUCCESS = FAILED = TIMEOUT = DURATION = TOOL_CALLS = None
    INPUT_TOKENS = OUTPUT_TOKENS = RISK = CONFIDENCE = None


def snapshot() -> dict[str, int]:
    return dict(_COUNTS)


def record_start() -> None:
    _COUNTS["runs"] += 1
    if RUNS is not None:
        RUNS.inc()


def record_queued() -> None:
    _COUNTS["queued"] += 1


def record_finish(
    *,
    status: str,
    duration_ms: int,
    tool_calls: int,
    input_tokens: int,
    output_tokens: int,
    risk_score: float,
    confidence: float,
) -> None:
    key = "success" if status == "completed" else "timeout" if status == "timeout" else "failed"
    _COUNTS[key] += 1
    mapping: list[tuple[Any, Any]] = [
        (SUCCESS if key == "success" else FAILED if key == "failed" else TIMEOUT, 1),
        (DURATION, duration_ms),
        (TOOL_CALLS, tool_calls),
        (INPUT_TOKENS, input_tokens),
        (OUTPUT_TOKENS, output_tokens),
        (RISK, risk_score),
        (CONFIDENCE, confidence),
    ]
    for metric, value in mapping:
        if metric is None:
            continue
        try:
            if hasattr(metric, "observe"):
                metric.observe(value)
            elif hasattr(metric, "inc") and metric in {SUCCESS, FAILED, TIMEOUT}:
                metric.inc()
        except Exception:  # noqa: BLE001
            pass
