"""Agent runtime — audit wrap, timeout, loop limit (spec §10 / §48)."""

from __future__ import annotations

import asyncio
from typing import Any

from .audit import AuditSink, InMemoryAuditSink
from .contracts import AgentContext, AgentResult, hash_payload
from .registry import AgentRegistry


class AgentLoopLimitError(RuntimeError):
    pass


class AgentRuntime:
    def __init__(
        self,
        registry: AgentRegistry,
        audit: AuditSink | None = None,
    ) -> None:
        self._registry = registry
        self._audit = audit or InMemoryAuditSink()

    @property
    def audit(self) -> AuditSink:
        return self._audit

    async def run(self, agent_name: str, context: AgentContext) -> AgentResult:
        if context.iteration >= context.constraints.max_iterations:
            raise AgentLoopLimitError(
                f"iteration {context.iteration} exceeds max {context.constraints.max_iterations}"
            )
        agent = self._registry.get(agent_name)
        started: dict[str, Any] = {
            "type": "AGENT_STARTED",
            "incidentId": context.incident_id,
            "tenantId": context.tenant_id,
            "correlationId": context.correlation_id,
            "agent": agent.name,
            "version": agent.version,
            "input": hash_payload(context.objective),
        }
        await self._audit.log(started)
        timeout_s = context.constraints.timeout_ms / 1000.0
        try:
            result = await asyncio.wait_for(agent.execute(context), timeout=timeout_s)
        except Exception as exc:
            await self._audit.log(
                {
                    "type": "AGENT_FAILED",
                    "incidentId": context.incident_id,
                    "tenantId": context.tenant_id,
                    "correlationId": context.correlation_id,
                    "agent": agent.name,
                    "version": agent.version,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            raise
        await self._audit.log(
            {
                "type": "AGENT_COMPLETED",
                "incidentId": context.incident_id,
                "tenantId": context.tenant_id,
                "correlationId": context.correlation_id,
                "agent": agent.name,
                "version": agent.version,
                "result": {
                    "status": result.status,
                    "confidence": result.confidence,
                    "findings": len(result.findings),
                    "hash": hash_payload(result.model_dump(mode="json")),
                },
            }
        )
        return result
