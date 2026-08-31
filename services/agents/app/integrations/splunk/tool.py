"""Splunk search tool for Agentic Investigation (Phase 8.7)."""

from __future__ import annotations

import time
from typing import Any

import structlog

from app.runtime.contracts import AgentContext, Evidence

from .client import SplunkClient, hash_query
from .config import SplunkConfig, load_splunk_config
from .errors import SplunkError, SplunkQueryValidationError
from .metrics import record_splunk_metric
from .models import SplunkSearchInput, SplunkSearchResult
from .normalizer import build_search_result, evidence_from_splunk_event, normalize_splunk_results
from .spl_policy import ensure_search_prefix, validate_spl_query

logger = structlog.get_logger()


def _ensure_tool_budget(context: AgentContext | None, config: SplunkConfig) -> None:
    if context is None:
        return
    count = int(context.metadata.get("splunk_tool_calls", 0))
    if count >= config.max_tool_calls_per_investigation:
        raise SplunkQueryValidationError(
            f"Splunk tool call budget exceeded ({config.max_tool_calls_per_investigation})"
        )


def _record_tool_metadata(context: AgentContext | None, result: SplunkSearchResult) -> None:
    if context is None:
        return
    context.metadata["splunk_tool_calls"] = int(context.metadata.get("splunk_tool_calls", 0)) + 1
    context.metadata["splunk_status"] = result.status
    context.metadata["splunk_events"] = int(context.metadata.get("splunk_events", 0)) + result.event_count
    history = list(context.metadata.get("splunk_tool_metadata") or [])
    history.append(
        {
            "tool": "splunk_search",
            "status": result.status,
            "search_id": result.search_id,
            "event_count": result.event_count,
            "truncated": result.truncated,
            "duration_ms": result.duration_ms,
            "query_hash": result.query_hash,
        }
    )
    context.metadata["splunk_tool_metadata"] = history


async def run_splunk_search(
    query: str,
    *,
    earliest: str | None = None,
    latest: str | None = "now",
    max_events: int = 100,
    context: AgentContext | None = None,
    agent_name: str = "investigation",
    agent_version: str = "2.0",
) -> SplunkSearchResult:
    """Execute a bounded read-only Splunk search."""
    config = load_splunk_config()
    if not config.enabled:
        result = build_search_result(status="SPLUNK_UNAVAILABLE", search_id=None, events=[], truncated=False, duration_ms=0)
        _record_tool_metadata(context, result)
        return result
    if not config.base_url or not config.username or not config.password:
        result = build_search_result(status="SPLUNK_UNAVAILABLE", search_id=None, events=[], truncated=False, duration_ms=0)
        _record_tool_metadata(context, result)
        return result
    search_input = SplunkSearchInput(query=query, earliest=earliest, latest=latest, max_events=max_events)
    try:
        _ensure_tool_budget(context, config)
        validate_spl_query(
            search_input.query,
            max_length=config.max_query_length,
            max_window_minutes=config.max_query_window_minutes,
            earliest=search_input.earliest,
            latest=search_input.latest,
            max_events=search_input.max_events,
            max_events_cap=config.max_events_per_query,
        )
    except SplunkQueryValidationError as exc:
        record_splunk_metric("splunk_query_rejected_total")
        result = build_search_result(
            status="SPLUNK_QUERY_REJECTED",
            search_id=None,
            events=[],
            truncated=False,
            duration_ms=0,
            error=str(exc),
            query_hash=hash_query(search_input.query),
        )
        _record_tool_metadata(context, result)
        return result
    spl = ensure_search_prefix(search_input.query)
    query_hash = hash_query(spl)
    if context is not None:
        seen = set(context.metadata.get("splunk_query_hashes") or [])
        if query_hash in seen:
            record_splunk_metric("splunk_query_rejected_total")
            result = build_search_result(
                status="SPLUNK_QUERY_REJECTED",
                search_id=None,
                events=[],
                truncated=False,
                duration_ms=0,
                error="duplicate Splunk query in this investigation",
                query_hash=query_hash,
            )
            _record_tool_metadata(context, result)
            return result
        seen.add(query_hash)
        context.metadata["splunk_query_hashes"] = list(seen)
    client = SplunkClient(config)
    started = time.monotonic()
    try:
        sid, rows, duration_ms = await client.search(
            spl,
            earliest=search_input.earliest,
            latest=search_input.latest,
            max_events=search_input.max_events,
        )
        events, truncated = normalize_splunk_results(rows, search_id=sid, max_events=search_input.max_events)
        status = "SUCCESS_WITH_RESULTS" if events else "SUCCESS_NO_RESULTS"
        result = build_search_result(
            status=status,
            search_id=sid,
            events=events,
            truncated=truncated,
            duration_ms=duration_ms,
            query_hash=hash_query(spl),
        )
        if events:
            record_splunk_metric("splunk_success_total")
        else:
            record_splunk_metric("splunk_no_results_total")
        _attach_evidence(context, events, search_id=sid, agent_name=agent_name, agent_version=agent_version)
        _record_tool_metadata(context, result)
        return result
    except SplunkError as exc:
        record_splunk_metric("splunk_query_errors_total")
        result = build_search_result(
            status=exc.status,  # type: ignore[arg-type]
            search_id=None,
            events=[],
            truncated=False,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=str(exc),
            query_hash=hash_query(spl),
        )
        _record_tool_metadata(context, result)
        return result


def _attach_evidence(
    context: AgentContext | None,
    events: list[Any],
    *,
    search_id: str,
    agent_name: str,
    agent_version: str,
) -> list[Evidence]:
    if context is None:
        return []
    created: list[Evidence] = []
    pending = list(context.metadata.get("splunk_pending_evidence") or [])
    for event in events:
        evidence = evidence_from_splunk_event(
            context,
            event,
            search_id=search_id,
            agent_name=agent_name,
            agent_version=agent_version,
        )
        pending.append(evidence.model_dump(mode="json"))
        created.append(evidence)
    context.metadata["splunk_pending_evidence"] = pending
    return created
