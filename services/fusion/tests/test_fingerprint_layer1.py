"""Layer-1 fingerprint stability and concurrency-oriented register races."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from app.models.alert import AlertSeverity, RawAlert
from app.services.deduplicator import Deduplicator


_TENANT = UUID("00000000-0000-0000-0000-000000000001")


def _alert(**kwargs) -> RawAlert:
    base = dict(
        id=uuid4(),
        tenant_id=_TENANT,
        source="splunk",
        title="t",
        severity=AlertSeverity.MEDIUM,
        source_event_ids=["stable-1"],
    )
    base.update(kwargs)
    return RawAlert(**base)


def test_same_source_event_same_fingerprint() -> None:
    assert _alert().fingerprint() == _alert().fingerprint()


def test_different_event_ids_different_fingerprint() -> None:
    assert _alert(source_event_ids=["a"]).fingerprint() != _alert(
        source_event_ids=["b"]
    ).fingerprint()


def test_different_tenants_different_fingerprint() -> None:
    other = UUID("00000000-0000-0000-0000-000000000002")
    assert _alert().fingerprint() != _alert(tenant_id=other).fingerprint()


@pytest.mark.asyncio
async def test_concurrent_register_only_one_wins() -> None:
    class _Redis:
        def __init__(self) -> None:
            self.store: dict[str, bytes] = {}

        async def get(self, key: str) -> bytes | None:
            return self.store.get(key)

        async def set(self, key, value, ex=None, nx=None):
            if nx and key in self.store:
                return None
            self.store[key] = value.encode() if isinstance(value, str) else value
            return True

    dedup = Deduplicator(_Redis())  # type: ignore[arg-type]
    a1, a2 = _alert(), _alert()
    # Same fingerprint (same event id) — second register loses NX race.
    assert await dedup.register(a1) is True
    assert await dedup.register(a2) is False
