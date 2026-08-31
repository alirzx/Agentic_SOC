"""Normalize Splunk events into Agentic Evidence records (Phase 8.7)."""

from __future__ import annotations

from typing import Any

from app.runtime.contracts import AgentContext, Evidence, EvidenceProvenance

from .models import SplunkEventRecord, SplunkSearchResult


def _first_field(row: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def normalize_splunk_event(row: dict[str, Any], *, search_id: str, event_index: int) -> SplunkEventRecord:
    host = _first_field(row, "host", "hostname")
    src_ip = _first_field(row, "src_ip", "src", "source_ip", "ClientIP", "IpAddress")
    dest_ip = _first_field(row, "dest_ip", "dest", "destination_ip", "dest_ip")
    user = _first_field(row, "user", "username", "user_name", "AccountName")
    return SplunkEventRecord(
        evidence_id=f"splunk:{search_id}:{event_index}",
        event_time=_first_field(row, "_time", "time"),
        host=host,
        src_ip=src_ip,
        dest_ip=dest_ip,
        user=user,
        event_type=_first_field(row, "action", "EventCode", "signature", "event_type"),
        index=_first_field(row, "index"),
        sourcetype=_first_field(row, "sourcetype"),
        source=_first_field(row, "source"),
        fields={k: v for k, v in row.items() if k not in {"_raw", "_serial", "_si"}},
    )


def normalize_splunk_results(
    rows: list[dict[str, Any]],
    *,
    search_id: str,
    max_events: int,
) -> tuple[list[SplunkEventRecord], bool]:
    events: list[SplunkEventRecord] = []
    truncated = len(rows) > max_events
    for idx, row in enumerate(rows[:max_events]):
        if isinstance(row, dict):
            events.append(normalize_splunk_event(row, search_id=search_id, event_index=idx))
    return events, truncated


def evidence_from_splunk_event(
    context: AgentContext,
    event: SplunkEventRecord,
    *,
    search_id: str,
    agent_name: str,
    agent_version: str,
) -> Evidence:
    return Evidence(
        id=event.evidence_id,
        incident_id=context.incident_id,
        type="splunk_event",
        source="splunk",
        data={
            "source": "splunk",
            "siem": "splunk",
            "search_id": search_id,
            "event_time": event.event_time,
            "host": event.host,
            "src_ip": event.src_ip,
            "dest_ip": event.dest_ip,
            "user": event.user,
            "index": event.index,
            "sourcetype": event.sourcetype,
            "fields": event.fields,
        },
        confidence=0.85,
        provenance=EvidenceProvenance(
            agent=agent_name,
            agent_version=agent_version,
            tool="splunk_search",
            source="splunk",
        ),
    )


def build_search_result(
    *,
    status: str,
    search_id: str | None,
    events: list[SplunkEventRecord],
    truncated: bool,
    duration_ms: int,
    query_hash: str | None = None,
    error: str | None = None,
) -> SplunkSearchResult:
    event_count = len(events)
    final_status = status
    if status == "SUCCESS_WITH_RESULTS" and event_count == 0:
        final_status = "SUCCESS_NO_RESULTS"
    if truncated and event_count > 0:
        final_status = "SPLUNK_RESULT_TRUNCATED"
    return SplunkSearchResult(
        status=final_status,  # type: ignore[arg-type]
        search_id=search_id,
        event_count=event_count,
        truncated=truncated,
        duration_ms=duration_ms,
        events=events,
        error=error,
        query_hash=query_hash,
    )
