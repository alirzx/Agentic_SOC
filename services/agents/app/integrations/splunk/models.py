"""Splunk search models (Phase 8.7)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

SplunkStatus = Literal[
    "SUCCESS_WITH_RESULTS",
    "SUCCESS_NO_RESULTS",
    "SPLUNK_UNAVAILABLE",
    "SPLUNK_AUTH_FAILURE",
    "SPLUNK_AUTHORIZATION_FAILURE",
    "SPLUNK_TIMEOUT",
    "SPLUNK_QUERY_REJECTED",
    "SPLUNK_QUERY_ERROR",
    "SPLUNK_RESULT_TRUNCATED",
]


class SplunkSearchInput(BaseModel):
    query: str
    earliest: str | None = None
    latest: str | None = "now"
    max_events: int = Field(default=100, ge=1, le=500)


class SplunkEventRecord(BaseModel):
    evidence_id: str
    event_time: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    user: str | None = None
    event_type: str | None = None
    index: str | None = None
    sourcetype: str | None = None
    source: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)


class SplunkSearchResult(BaseModel):
    status: SplunkStatus
    source: str = "splunk"
    search_id: str | None = None
    event_count: int = 0
    truncated: bool = False
    duration_ms: int = 0
    events: list[SplunkEventRecord] = Field(default_factory=list)
    error: str | None = None
    query_hash: str | None = None
