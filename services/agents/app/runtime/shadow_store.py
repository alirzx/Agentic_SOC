"""In-memory + Postgres persistence for AgenticShadowRun (Phase 7)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.runtime.contracts import utcnow


class ShadowRunRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    alert_id: str
    case_id: str = ""
    status: str = "created"
    agent_version: str = "runtime/v1.0"
    workflow_version: str = "agentic-shadow-v1"
    prompt_version: str = "agentic-soc-runtime/v1"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int = 0
    risk_score: float = 0.0
    confidence: float = 0.0
    decision: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    tool_call_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost: float = 0.0
    error: str | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    comparison: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class InMemoryShadowStore:
    def __init__(self) -> None:
        self._by_id: dict[str, ShadowRunRecord] = {}
        self._by_alert: dict[tuple[str, str], str] = {}

    def get(self, run_id: str) -> ShadowRunRecord | None:
        return self._by_id.get(run_id)

    def get_by_alert(self, tenant_id: str, alert_id: str) -> ShadowRunRecord | None:
        run_id = self._by_alert.get((tenant_id, alert_id))
        return self._by_id.get(run_id) if run_id else None

    def list_for_tenant(self, tenant_id: str) -> list[ShadowRunRecord]:
        return [row for row in self._by_id.values() if row.tenant_id == tenant_id]

    def save(self, record: ShadowRunRecord) -> ShadowRunRecord:
        self._by_id[record.id] = record
        self._by_alert[(record.tenant_id, record.alert_id)] = record.id
        return record


class PostgresShadowStore:
    """Best-effort writes on the investigation-ledger pool. No-ops without DATABASE_URL."""

    def __init__(self) -> None:
        self._memory = InMemoryShadowStore()

    async def save(self, record: ShadowRunRecord) -> ShadowRunRecord:
        self._memory.save(record)
        try:
            from app.investigator import ledger as ledger_module
        except ImportError:
            return record
        pool = await ledger_module.get_pool()
        if pool is None:
            return record
        try:
            tenant_uuid = UUID(record.tenant_id)
        except ValueError:
            return record
        try:
            async with pool.acquire() as conn:
                await ledger_module._set_rls_context(conn, tenant_uuid)
                await conn.execute(
                    """
                    INSERT INTO agentic_shadow_runs (
                        id, tenant_id, alert_id, case_id, status,
                        agent_version, workflow_version, prompt_version,
                        started_at, completed_at, duration_ms,
                        risk_score, confidence, decision, recommended_actions,
                        tool_call_count, input_tokens, output_tokens, estimated_cost,
                        error, evidence, comparison, result, created_at
                    ) VALUES (
                        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,
                        $16,$17,$18,$19,$20,$21::jsonb,$22::jsonb,$23::jsonb,$24
                    )
                    ON CONFLICT (tenant_id, alert_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        completed_at = EXCLUDED.completed_at,
                        duration_ms = EXCLUDED.duration_ms,
                        risk_score = EXCLUDED.risk_score,
                        confidence = EXCLUDED.confidence,
                        decision = EXCLUDED.decision,
                        recommended_actions = EXCLUDED.recommended_actions,
                        tool_call_count = EXCLUDED.tool_call_count,
                        input_tokens = EXCLUDED.input_tokens,
                        output_tokens = EXCLUDED.output_tokens,
                        estimated_cost = EXCLUDED.estimated_cost,
                        error = EXCLUDED.error,
                        evidence = EXCLUDED.evidence,
                        comparison = EXCLUDED.comparison,
                        result = EXCLUDED.result
                    """,
                    UUID(record.id),
                    tenant_uuid,
                    record.alert_id,
                    record.case_id,
                    record.status,
                    record.agent_version,
                    record.workflow_version,
                    record.prompt_version,
                    record.started_at,
                    record.completed_at,
                    record.duration_ms,
                    record.risk_score,
                    record.confidence,
                    record.decision,
                    json.dumps(record.recommended_actions),
                    record.tool_call_count,
                    record.input_tokens,
                    record.output_tokens,
                    record.estimated_cost,
                    record.error,
                    json.dumps(record.evidence),
                    json.dumps(record.comparison),
                    json.dumps(record.result),
                    record.created_at,
                )
        except Exception:  # noqa: BLE001 — isolation: never raise into Kafka
            return record
        return record

    def get(self, run_id: str) -> ShadowRunRecord | None:
        return self._memory.get(run_id)

    def get_by_alert(self, tenant_id: str, alert_id: str) -> ShadowRunRecord | None:
        return self._memory.get_by_alert(tenant_id, alert_id)

    def list_for_tenant(self, tenant_id: str) -> list[ShadowRunRecord]:
        return self._memory.list_for_tenant(tenant_id)
