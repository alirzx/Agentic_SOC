import uuid

import pytest
from app.core.config import settings
from app.models.alert import AlertSeverity, RawAlert
from app.services.fusion_engine import FusionEngine


class _DedupNeverDuplicate:
    async def is_duplicate(self, alert):
        return False, None

    async def register(self, alert):
        return True


class _CorrelatorMustNotRun:
    async def correlate(self, alert):
        raise AssertionError("legacy fusion correlator ran while disabled")


@pytest.mark.asyncio
async def test_legacy_fusion_correlator_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AISOC_LEGACY_FUSION_CORRELATOR", raising=False)
    monkeypatch.setattr(settings, "legacy_fusion_correlator_enabled", False)

    engine = FusionEngine(_DedupNeverDuplicate(), _CorrelatorMustNotRun())
    alert = RawAlert(
        tenant_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        source="test",
        title="Standalone alert",
        severity=AlertSeverity.HIGH,
    )

    fused = await engine.process(alert)

    assert fused.incident_id is None
    assert fused.fusion_decision.value == "new_alert"
