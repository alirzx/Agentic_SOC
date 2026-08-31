"""Agentic SOC feature flags (Phase 7). Uses os.getenv like existing workers."""

from __future__ import annotations

import os


def _truthy(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def enabled() -> bool:
    return _truthy("AGENTIC_SOC_ENABLED", "0")


def shadow_mode() -> bool:
    """Default on so a mistaken ENABLED=true still cannot fire live response."""
    return _truthy("AGENTIC_SOC_SHADOW_MODE", "1")


def auto_response() -> bool:
    return _truthy("AGENTIC_SOC_AUTO_RESPONSE", "0")


def max_concurrent_runs() -> int:
    try:
        return max(1, int(os.getenv("AGENTIC_SOC_MAX_CONCURRENT_RUNS", "10")))
    except ValueError:
        return 10


def timeout_seconds() -> float:
    try:
        return max(1.0, float(os.getenv("AGENTIC_SOC_TIMEOUT_SECONDS", "120")))
    except ValueError:
        return 120.0


def must_dry_run_tools() -> bool:
    """Shadow mode always wins over AUTO_RESPONSE."""
    if not enabled():
        return True
    return shadow_mode() or not auto_response()
