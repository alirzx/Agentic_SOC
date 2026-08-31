"""Configurable iteration limits for LLM agents (Phase 8.6)."""

from __future__ import annotations

import os


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return max(0.1, float(os.getenv(name, str(default))))
    except ValueError:
        return default


def max_investigation_iterations() -> int:
    return _int_env("AGENTIC_MAX_INVESTIGATION_ITERATIONS", 12)


def max_tool_calls() -> int:
    return _int_env("AGENTIC_MAX_TOOL_CALLS", 20)


def max_llm_calls() -> int:
    return _int_env("AGENTIC_MAX_LLM_CALLS", 15)


def max_investigation_seconds() -> float:
    return _float_env("AGENTIC_MAX_INVESTIGATION_SECONDS", 90.0)


def max_cost_per_incident() -> float | None:
    raw = os.getenv("AGENTIC_MAX_COST_PER_INCIDENT", "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None
