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


from .sysmon_parser import merge_sysmon_into_row


def normalize_splunk_event(row: dict[str, Any], *, search_id: str, event_index: int) -> SplunkEventRecord:
    enriched = merge_sysmon_into_row(row)
    host = _first_field(enriched, "host", "hostname", "Computer")
    src_ip = _first_field(enriched, "src_ip", "src", "source_ip", "ClientIP", "IpAddress")
    dest_ip = _first_field(enriched, "dest_ip", "dest", "destination_ip", "dest_ip")
    user = _first_field(enriched, "user", "username", "user_name", "AccountName", "User")
    event_type = _first_field(enriched, "EventID", "action", "EventCode", "signature", "event_type")
    index_name = _first_field(enriched, "index")
    raw = enriched.get("_raw")
    fields = {
        k: v
        for k, v in enriched.items()
        if k not in {"_serial", "_si", "_bkt", "_cd"}
    }
    if raw is not None:
        fields["_raw"] = str(raw)
    if enriched.get("sysmon"):
        fields["sysmon"] = enriched["sysmon"]
    if enriched.get("Image"):
        fields["Image"] = enriched["Image"]
    if enriched.get("CommandLine"):
        fields["CommandLine"] = enriched["CommandLine"]
    if enriched.get("ParentImage"):
        fields["ParentImage"] = enriched["ParentImage"]
    if enriched.get("Hashes"):
        fields["Hashes"] = enriched["Hashes"]
    return SplunkEventRecord(
        evidence_id=f"splunk:{search_id}:{event_index}",
        event_time=_first_field(enriched, "_time", "time", "UtcTime"),
        host=host,
        src_ip=src_ip,
        dest_ip=dest_ip,
        user=user,
        event_type=event_type,
        index=index_name,
        sourcetype=_first_field(enriched, "sourcetype"),
        source=_first_field(enriched, "source"),
        fields=fields,
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
            "evidence_id": event.evidence_id,
            "event_time": event.event_time,
            "host": event.host,
            "src_ip": event.src_ip,
            "dest_ip": event.dest_ip,
            "user": event.user,
            "event_type": event.event_type,
            "index": event.index,
            "sourcetype": event.sourcetype,
            "fields": event.fields,
            "_raw": event.fields.get("_raw"),
            "sysmon": event.fields.get("sysmon"),
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
