"""Asset enrichment fail-soft behavior (no live DB required)."""

from __future__ import annotations

import pytest
from app.enrichment import asset_context as ac


@pytest.mark.asyncio
async def test_disabled_returns_cleanly(monkeypatch):
    monkeypatch.setenv("AISOC_ASSET_ENRICH_ENABLED", "0")
    out = await ac.enrich_alert_assets(tenant_id="11111111-1111-1111-1111-111111111111", hostname="host1")
    assert out.found is False
    assert out.reason == "disabled"


@pytest.mark.asyncio
async def test_no_keys_short_circuits(monkeypatch):
    monkeypatch.setenv("AISOC_ASSET_ENRICH_ENABLED", "1")
    out = await ac.enrich_alert_assets(tenant_id="11111111-1111-1111-1111-111111111111")
    assert out.reason == "no_lookup_keys"


def test_criticality_points_bounded():
    assert ac.criticality_points("critical") == 20
    assert ac.criticality_points("unknown") == 0
