"""Unit tests for SLA duration derivation and hybrid metrics."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.sla import (
    DEFAULT_SLA_TARGETS,
    _compute_durations,
    compute_sla_metrics,
    durations_from_alert,
)


def _alert(**kwargs: object) -> SimpleNamespace:
    base = {
        "id": uuid.uuid4(),
        "severity": "high",
        "status": "new",
        "first_seen": datetime(2026, 11, 1, 10, 0, tzinfo=UTC),
        "created_at": datetime(2026, 11, 1, 10, 0, tzinfo=UTC),
        "event_time": datetime(2026, 11, 1, 9, 55, tzinfo=UTC),
        "first_seen_at": None,
        "assigned_at": None,
        "resolved_at": None,
        "updated_at": datetime(2026, 11, 1, 10, 0, tzinfo=UTC),
    }
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_durations_from_alert_mttd_mttr_mttc() -> None:
    detected = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
    ack = detected + timedelta(minutes=12)
    resolved = detected + timedelta(minutes=45)
    closed = detected + timedelta(minutes=90)
    alert = _alert(
        first_seen=detected,
        first_seen_at=ack,
        status="closed",
        resolved_at=resolved,
        updated_at=closed,
    )
    # For closed status, closed uses resolved_at or updated_at — resolved_at wins.
    alert.resolved_at = closed
    actual = durations_from_alert(alert)  # type: ignore[arg-type]
    assert actual["mttd"] == 12
    assert actual["mttr"] is None  # status closed, not resolved
    assert actual["mttc"] == 90
    assert actual["severity"] == "high"
    assert actual["source"] == "alert_timestamps"


def test_durations_from_alert_resolved_path() -> None:
    detected = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
    alert = _alert(
        first_seen=detected,
        assigned_at=detected + timedelta(minutes=20),
        status="resolved",
        resolved_at=detected + timedelta(minutes=55),
    )
    actual = durations_from_alert(alert)  # type: ignore[arg-type]
    assert actual["mttd"] == 20
    assert actual["mttr"] == 55
    assert actual["mttc"] is None


def test_compute_durations_from_events() -> None:
    alert_id = uuid.uuid4()
    t0 = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
    events = [
        SimpleNamespace(alert_id=alert_id, event_type="detected", occurred_at=t0, severity="critical"),
        SimpleNamespace(
            alert_id=alert_id,
            event_type="acknowledged",
            occurred_at=t0 + timedelta(minutes=5),
            severity="critical",
        ),
        SimpleNamespace(
            alert_id=alert_id,
            event_type="resolved",
            occurred_at=t0 + timedelta(minutes=40),
            severity="critical",
        ),
        SimpleNamespace(
            alert_id=alert_id,
            event_type="closed",
            occurred_at=t0 + timedelta(minutes=70),
            severity="critical",
        ),
    ]
    actual = _compute_durations(events)  # type: ignore[arg-type]
    assert actual["mttd"] == 5
    assert actual["mttr"] == 40
    assert actual["mttc"] == 70
    assert actual["severity"] == "critical"


@pytest.mark.asyncio
async def test_compute_sla_metrics_hybrid_uses_alert_fallback() -> None:
    tenant_id = uuid.uuid4()
    detected = datetime.now(UTC) - timedelta(days=2)
    alert = _alert(
        id=uuid.uuid4(),
        first_seen=detected,
        created_at=detected,
        first_seen_at=detected + timedelta(minutes=10),
        status="resolved",
        resolved_at=detected + timedelta(minutes=50),
        severity="critical",
    )
    derived = durations_from_alert(alert)  # type: ignore[arg-type]
    db = AsyncMock()

    from unittest.mock import patch

    with (
        patch("app.services.sla.get_settings") as gs,
        patch("app.services.sla.ensure_tenant_sla_config", new_callable=AsyncMock) as ensure_cfg,
        patch("app.services.sla._get_sla_configs", new_callable=AsyncMock) as get_cfg,
        patch("app.services.sla._fetch_alert_events", new_callable=AsyncMock) as fetch_ev,
        patch("app.services.sla._durations_from_alerts", new_callable=AsyncMock) as from_alerts,
    ):
        gs.return_value = SimpleNamespace(AISOC_FEATURE_KPI_BAR=False)
        ensure_cfg.return_value = 5
        get_cfg.return_value = {}
        fetch_ev.return_value = {}
        from_alerts.return_value = {derived["alert_id"]: derived}
        metrics = await compute_sla_metrics(db, tenant_id, days=30)

    assert metrics["overall"]["total_alerts"] == 1
    assert metrics["overall"]["data_source"] == "hybrid_alerts_and_sla_events"
    assert metrics["per_severity"]["critical"]["total"] == 1
    assert metrics["per_severity"]["critical"]["mttd_avg"] == 10.0
    assert metrics["per_severity"]["critical"]["mttr_avg"] == 50.0
    assert metrics["per_severity"]["critical"]["mttd_target"] == DEFAULT_SLA_TARGETS["critical"]["mttd_target"]
