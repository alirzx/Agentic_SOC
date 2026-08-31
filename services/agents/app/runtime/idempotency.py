"""Idempotency keys for incident/agent runs (spec §41)."""

from __future__ import annotations

from .contracts import hash_payload


class IdempotencyStore:
    def __init__(self) -> None:
        self._seen: dict[str, str] = {}

    def key(self, *, tenant_id: str, incident_id: str, agent: str, objective: str) -> str:
        return hash_payload(
            {
                "tenant_id": tenant_id,
                "incident_id": incident_id,
                "agent": agent,
                "objective": objective,
            }
        )

    def seen(self, key: str) -> bool:
        return key in self._seen

    def remember(self, key: str, result_hash: str) -> None:
        self._seen[key] = result_hash

    def result_hash(self, key: str) -> str | None:
        return self._seen.get(key)
