"""Lightweight Splunk request metrics (Phase 8.7)."""

from __future__ import annotations

from collections import Counter

import structlog

logger = structlog.get_logger()

_COUNTERS: Counter[str] = Counter()


def record_splunk_metric(name: str, *, value: int = 1) -> None:
    _COUNTERS[name] += value
    logger.info("splunk.metric", metric=name, value=value, total=_COUNTERS[name])


def splunk_metrics_snapshot() -> dict[str, int]:
    return dict(_COUNTERS)


def reset_splunk_metrics() -> None:
    _COUNTERS.clear()
