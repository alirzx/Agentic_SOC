"""Deduplicator: Redis window plus durable Postgres fingerprint lookup."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from app.models.alert import AlertSeverity, RawAlert
from app.services.deduplicator import Deduplicator

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


class _FakeSink:
    def __init__(self, found: str | None = None) -> None:
        self.found = found
        self.calls: list[tuple[UUID, str]] = []
        self.touches: list[tuple] = []

    async def lookup_dedup(self, tenant_id, fingerprint: str) -> str | None:
        self.calls.append((tenant_id, fingerprint))
        return self.found

    async def touch_duplicate(self, tenant_id, fingerprint: str, *, event_time=None, original_id=None) -> bool:
        self.touches.append((tenant_id, fingerprint, event_time, original_id))
        return True


def _alert() -> RawAlert:
    return RawAlert(
        id=uuid4(),
        tenant_id=_TENANT,
        source="splunk",
        title="Network - Unapproved Port Activity Detected - Rule",
        severity=AlertSeverity.MEDIUM,
        hostname="WIN-017UMT7DCGT.soorinsec.local",
        source_event_ids=["stable-notable-1"],
        rule_id="Network - Unapproved Port Activity Detected - Rule",
    )


@pytest.mark.asyncio
async def test_postgres_lookup_on_redis_miss() -> None:
    original = str(uuid4())
    sink = _FakeSink(found=original)
    dedup = Deduplicator(_FakeRedis(), sink=sink)  # type: ignore[arg-type]
    is_dup, found = await dedup.is_duplicate(_alert())
    assert is_dup is True
    assert found == original
    assert sink.calls


@pytest.mark.asyncio
async def test_not_duplicate_when_redis_and_postgres_miss() -> None:
    sink = _FakeSink(found=None)
    dedup = Deduplicator(_FakeRedis(), sink=sink)  # type: ignore[arg-type]
    is_dup, found = await dedup.is_duplicate(_alert())
    assert is_dup is False
    assert found is None


@pytest.mark.asyncio
async def test_register_set_nx_second_loses() -> None:
    redis = _FakeRedis()
    dedup = Deduplicator(redis, sink=_FakeSink())  # type: ignore[arg-type]
    a1 = _alert()
    a2 = _alert()
    assert await dedup.register(a1) is True
    assert await dedup.register(a2) is False


@pytest.mark.asyncio
async def test_duplicate_touches_canonical_row() -> None:
    original = str(uuid4())
    sink = _FakeSink(found=original)
    redis = _FakeRedis()
    dedup = Deduplicator(redis, sink=sink)  # type: ignore[arg-type]
    await dedup.register(_alert())
    # Force redis hit path
    is_dup, found = await dedup.is_duplicate(_alert())
    assert is_dup is True
    assert found
    assert sink.touches
