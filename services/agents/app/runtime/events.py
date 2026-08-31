"""Typed Kafka incident-lifecycle events (spec §39–40). Producers stay in existing workers."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from .contracts import utcnow
from .incident import IncidentState

IncidentEventType = Literal[
    "incident.created",
    "incident.state_changed",
    "agent.started",
    "agent.completed",
    "agent.failed",
    "evidence.appended",
    "approval.requested",
    "approval.decided",
    "response.executed",
    "report.generated",
]


class IncidentLifecycleEvent(BaseModel):
    type: IncidentEventType
    incident_id: str
    tenant_id: str
    correlation_id: str
    state: IncidentState
    payload: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=utcnow)
    idempotency_key: str = ""
