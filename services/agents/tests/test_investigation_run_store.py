"""Unit tests for the durable investigation run poll-store."""

from __future__ import annotations

import pytest

from app.api import investigation_run_store as store


@pytest.mark.asyncio
async def test_put_get_roundtrip_memory_fallback() -> None:
    store.clear_memory_for_tests()
    run_id = "11111111-1111-1111-1111-111111111111"
    await store.put_run(run_id, {"id": run_id, "status": "running", "_tenant_owner": "t1"})
    got = await store.get_run(run_id)
    assert got is not None
    assert got["status"] == "running"
    assert got["_tenant_owner"] == "t1"


@pytest.mark.asyncio
async def test_update_run_merges_fields() -> None:
    store.clear_memory_for_tests()
    run_id = "22222222-2222-2222-2222-222222222222"
    await store.put_run(run_id, {"id": run_id, "status": "running"})
    updated = await store.update_run(run_id, {"status": "completed", "findings": "ok"})
    assert updated is not None
    assert updated["status"] == "completed"
    assert updated["findings"] == "ok"
    assert updated["id"] == run_id


@pytest.mark.asyncio
async def test_update_missing_returns_none() -> None:
    store.clear_memory_for_tests()
    assert await store.update_run("missing-run", {"status": "failed"}) is None
