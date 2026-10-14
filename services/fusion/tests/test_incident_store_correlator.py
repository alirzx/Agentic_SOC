"""Durable incident restore after Redis miss."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import pytest
from app.models.alert import AlertSeverity, IncidentSummary, RawAlert
from app.services.correlator import Correlator

_TENANT = UUID("00000000-0000-0000-0000-000000000001")


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    async def get(self, key: str) -> bytes | None:
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None, nx: bool | None = None) -> bool | None:
        if nx and key in self.store:
            return None
        self.store[key] = value.encode() if isinstance(value, str) else value
        return True


class _FakeIncidentStore:
    def __init__(self) -> None:
        self.by_id: dict[UUID, IncidentSummary] = {}
        self.upserts: list[tuple[IncidentSummary, str]] = []

    async def upsert(self, incident: IncidentSummary, *, status: str = "open") -> bool:
        self.upserts.append((incident, status))
        self.by_id[incident.id] = incident
        return True

    async def find_open(self, tenant_id: UUID, correlation_key: str) -> IncidentSummary | None:
        for inc in self.by_id.values():
            if inc.tenant_id == tenant_id and correlation_key in (inc.correlation_keys or []):
                return inc
        return None

    async def get(self, incident_id: UUID) -> IncidentSummary | None:
        return self.by_id.get(incident_id)

    async def link_alert(self, incident_id, alert_id, tenant_id) -> bool:
        return True


def _alert(**kwargs) -> RawAlert:
    base = dict(
        id=uuid4(),
        tenant_id=_TENANT,
        source="splunk",
        title="Auth spray",
        severity=AlertSeverity.MEDIUM,
        src_ip="10.0.0.5",
        username="alice",
        mitre_tactics=["Credential Access"],
        mitre_techniques=["T1110.003"],
        event_time=datetime(2026, 10, 14, 12, 0, 0),
    )
    base.update(kwargs)
    return RawAlert(**base)


@pytest.mark.asyncio
async def test_redis_miss_restores_from_durable_store() -> None:
    store = _FakeIncidentStore()
    redis = _FakeRedis()
    corr = Correlator(redis, store=store)  # type: ignore[arg-type]
    a1 = _alert()
    _, inc1 = await corr.correlate(a1)
    assert store.upserts
    # Simulate Redis TTL wipe
    redis.store.clear()
    a2 = _alert(id=uuid4(), event_time=datetime(2026, 10, 14, 12, 10, 0))
    correlated, inc2 = await corr.correlate(a2)
    assert correlated is True
    assert inc2.id == inc1.id
    assert inc2.alert_count == 2


@pytest.mark.asyncio
async def test_new_incident_persists_and_links() -> None:
    store = _FakeIncidentStore()
    corr = Correlator(_FakeRedis(), store=store)  # type: ignore[arg-type]
    _, inc = await corr.correlate(_alert())
    assert any(u[0].id == inc.id for u in store.upserts)
