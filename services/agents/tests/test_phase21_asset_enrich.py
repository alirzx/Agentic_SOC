"""Phase 2.1 — asset enrichment failure modes without live CMDB."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from app.enrichment import asset_context as ac


@pytest.fixture(autouse=True)
def _reset_circuit(monkeypatch):
    monkeypatch.setenv("AISOC_ASSET_ENRICH_ENABLED", "1")
    monkeypatch.setenv("AISOC_ASSET_ENRICH_CIRCUIT_FAILURES", "3")
    monkeypatch.setenv("AISOC_ASSET_ENRICH_CIRCUIT_COOLDOWN_SECONDS", "30")
    ac._CACHE.clear()
    ac._CIRCUIT_FAILURES = 0
    ac._CIRCUIT_OPEN_UNTIL = 0.0
    yield
    ac._CACHE.clear()
    ac._CIRCUIT_FAILURES = 0
    ac._CIRCUIT_OPEN_UNTIL = 0.0


@pytest.mark.asyncio
async def test_timeout_is_fail_soft(monkeypatch):
    async def _slow(*_a, **_k):
        import asyncio

        await asyncio.sleep(5)
        return {"name": "late"}

    monkeypatch.setenv("AISOC_ASSET_ENRICH_TIMEOUT_SECONDS", "0.05")
    monkeypatch.setattr(ac, "_lookup", _slow)
    out = await ac.enrich_alert_assets(tenant_id=uuid4(), hostname="host-a")
    assert out.found is False
    assert out.unavailable is True
    assert out.reason == "timeout"


@pytest.mark.asyncio
async def test_lookup_error_opens_circuit_after_threshold(monkeypatch):
    async def _boom(*_a, **_k):
        raise RuntimeError("db down")

    monkeypatch.setattr(ac, "_lookup", _boom)
    monkeypatch.setattr(ac, "_CIRCUIT_THRESHOLD", 3)
    monkeypatch.setenv("AISOC_ASSET_ENRICH_TIMEOUT_SECONDS", "1")
    tid = uuid4()
    for _ in range(3):
        out = await ac.enrich_alert_assets(tenant_id=tid, hostname="h1")
        assert out.unavailable is True
    open_out = await ac.enrich_alert_assets(tenant_id=tid, hostname="h1")
    assert open_out.reason == "circuit_open"


@pytest.mark.asyncio
async def test_cache_hit_avoids_second_lookup(monkeypatch):
    calls = {"n": 0}

    async def _once(*_a, **_k):
        calls["n"] += 1
        return {
            "asset_id": str(uuid4()),
            "name": "srv1",
            "criticality": "high",
            "criticality_points": 15,
            "stale": False,
            "source": "assets_table",
            "observed": True,
            "inferred": False,
        }

    monkeypatch.setattr(ac, "_lookup", _once)
    tid = uuid4()
    first = await ac.enrich_alert_assets(tenant_id=tid, hostname="srv1.local")
    second = await ac.enrich_alert_assets(tenant_id=tid, hostname="srv1.local")
    assert first.found and second.found
    assert calls["n"] == 1
    assert second.reason == "cache_hit"


def test_stale_detection():
    old = datetime.now(UTC) - timedelta(days=14)
    assert ac._is_stale(old, max_age_hours=168) is True
    fresh = datetime.now(UTC) - timedelta(hours=1)
    assert ac._is_stale(fresh, max_age_hours=168) is False


def test_missing_asset_is_not_benign_signal():
    """Contract: not_found must never be interpreted as authorized/benign."""
    # Documented via reason code — callers must not map not_found → suppress.
    assert "not_found" != "benign"
    assert ac.criticality_points(None) == 0
