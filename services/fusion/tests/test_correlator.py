"""Unit tests for Redis correlator incident grouping."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest
from app.models.alert import AlertSeverity, RawAlert
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


def _alert(**kwargs) -> RawAlert:
    base = dict(
        id=uuid4(),
        tenant_id=_TENANT,
        source="splunk",
        title="Auth failures",
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
async def test_related_alerts_form_one_incident() -> None:
    corr = Correlator(_FakeRedis())  # type: ignore[arg-type]
    a1 = _alert()
    a2 = _alert(id=uuid4(), event_time=datetime(2026, 10, 14, 12, 5, 0))
    first_corr, inc1 = await corr.correlate(a1)
    second_corr, inc2 = await corr.correlate(a2)
    assert first_corr is False
    assert second_corr is True
    assert inc1.id == inc2.id
    assert inc2.alert_count == 2
    assert inc2.last_seen == a2.event_time


@pytest.mark.asyncio
async def test_unrelated_entity_stays_separate() -> None:
    corr = Correlator(_FakeRedis())  # type: ignore[arg-type]
    a1 = _alert(src_ip="10.0.0.5")
    a2 = _alert(id=uuid4(), src_ip="10.0.0.9", username="bob")
    _, inc1 = await corr.correlate(a1)
    _, inc2 = await corr.correlate(a2)
    assert inc1.id != inc2.id


@pytest.mark.asyncio
async def test_late_event_updates_last_seen_from_event_time() -> None:
    corr = Correlator(_FakeRedis())  # type: ignore[arg-type]
    early = datetime(2026, 10, 14, 10, 0, 0)
    late = early + timedelta(minutes=30)
    _, inc1 = await corr.correlate(_alert(event_time=early))
    _, inc2 = await corr.correlate(_alert(id=uuid4(), event_time=late))
    assert inc2.last_seen == late
    assert inc1.id == inc2.id
