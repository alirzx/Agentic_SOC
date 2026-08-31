"""Spec §8 agent contracts — Pydantic, not NestJS.

Existing LangGraph agents keep their own state models. This module is the
shared execute() boundary the runtime, registry, and adapters use.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

AgentResultStatus = Literal["success", "failed", "blocked"]
ToolRiskLevel = Literal["read", "low", "medium", "high", "critical"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_payload(payload: Any) -> str:
    """Deterministic SHA-256 of a JSON-serialisable value (spec §31)."""
    try:
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        encoded = str(payload).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class EvidenceProvenance(BaseModel):
    agent: str
    agent_version: str
    tool: str
    query_id: str | None = None
    source: str
    retrieved_at: datetime = Field(default_factory=utcnow)


class Evidence(BaseModel):
    """First-class evidence with provenance (spec §31)."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    type: str
    source: str
    data: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=utcnow)
    hash: str = ""
    provenance: EvidenceProvenance | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.hash:
            self.hash = hash_payload(self.data)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    statement: str
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    mitre_techniques: list[str] = Field(default_factory=list)


class AgentAction(BaseModel):
    name: str
    tool: str
    input: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] | None = None
    risk_level: ToolRiskLevel = "read"


class NextTask(BaseModel):
    """Spec AgentTask — named NextTask to avoid clashing with models.state.AgentTask."""

    agent: str
    objective: str
    priority: int = 0


class IncidentStateSnapshot(BaseModel):
    state: str = "NEW"
    severity: str | None = None
    risk_score: float = 0.0
    confidence: float = 0.0
    summary: dict[str, Any] = Field(default_factory=dict)
    raw_alert: dict[str, Any] = Field(default_factory=dict)


class AgentConstraints(BaseModel):
    max_iterations: int = Field(default=8, ge=1, le=32)
    max_tool_calls: int = Field(default=16, ge=1, le=64)
    timeout_ms: int = Field(default=120_000, ge=1_000, le=600_000)


class AgentContext(BaseModel):
    incident_id: str
    tenant_id: str
    objective: str
    state: IncidentStateSnapshot = Field(default_factory=IncidentStateSnapshot)
    evidence: list[Evidence] = Field(default_factory=list)
    previous_actions: list[AgentAction] = Field(default_factory=list)
    available_tools: list[str] = Field(default_factory=list)
    constraints: AgentConstraints = Field(default_factory=AgentConstraints)
    metadata: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    iteration: int = 0


class AgentResult(BaseModel):
    status: AgentResultStatus
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    actions: list[AgentAction] = Field(default_factory=list)
    next_tasks: list[NextTask] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str | None = None
    uncertainty: list[str] = Field(default_factory=list)


class Agent(ABC):
    """Versioned agent contract (spec §8 / §9)."""

    name: str
    version: str

    @property
    def qualified_name(self) -> str:
        return f"{self.name}:v{self.version}"

    @abstractmethod
    async def execute(self, context: AgentContext) -> AgentResult:
        raise NotImplementedError
