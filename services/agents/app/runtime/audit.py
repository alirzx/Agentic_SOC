"""Runtime audit sink (spec §10 / §45). Reuses the investigation ledger when wired."""

from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID

import structlog

from .contracts import hash_payload

logger = structlog.get_logger()


class AuditSink(Protocol):
    async def log(self, event: dict[str, Any]) -> None: ...


class InMemoryAuditSink:
    """Test and offline sink. Never silently drops events."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def log(self, event: dict[str, Any]) -> None:
        self.events.append(event)
        logger.info(
            "runtime.audit",
            type=str(event.get("type", "")).replace("\r", "").replace("\n", " ")[:80],
            agent=str(event.get("agent", "")).replace("\r", "").replace("\n", " ")[:80],
        )


class LedgerAuditSink:
    """Best-effort write to the existing investigation ledger."""

    def __init__(self, *, run_id: UUID, tenant_id: UUID) -> None:
        self._run_id = run_id
        self._tenant_id = tenant_id
        self._seq = 0
        self.events: list[dict[str, Any]] = []

    async def log(self, event: dict[str, Any]) -> None:
        self.events.append(event)
        self._seq += 1
        try:
            from app.investigator import ledger as ledger_module
        except ImportError:  # pragma: no cover - agents package always present in CI
            return
        kind = str(event.get("type", "agent_event")).lower()
        await ledger_module.record_event(
            run_id=self._run_id,
            tenant_id=self._tenant_id,
            seq=self._seq,
            kind=kind,
            agent=str(event.get("agent", "runtime")),
            summary=str(event.get("summary") or event.get("type") or "agent_event")[:8000],
            payload=event,
            input_hash=hash_payload(event.get("input")),
            output_hash=hash_payload(event.get("result") or event.get("error")),
        )
