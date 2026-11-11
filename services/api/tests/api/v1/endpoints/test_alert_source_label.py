"""Unit tests for alert connector source display labels."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

from app.api.v1.endpoints.alerts import _alert_source_label, _to_alert_response


def test_alert_source_label_prefers_connector_instance_name() -> None:
    actual = _alert_source_label(
        connector_name="Splunk SIEM 107 payload",
        connector_type="splunk",
    )
    assert actual == "Splunk SIEM 107 payload"


def test_alert_source_label_collapses_duplicate_product_label() -> None:
    actual = _alert_source_label(connector_name=None, connector_type="splunk splunk")
    assert actual == "splunk"


def test_alert_source_label_falls_back_to_unknown() -> None:
    actual = _alert_source_label(connector_name=None, connector_type=None)
    assert actual == "unknown"


def test_to_alert_response_sets_source_from_connector_name() -> None:
    connector_id = uuid.uuid4()
    now = datetime.now(UTC)
    alert = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        title="Test",
        description=None,
        severity="medium",
        status="new",
        priority=50,
        category=None,
        mitre_tactics=[],
        mitre_techniques=[],
        connector_type="splunk",
        connector_id=connector_id,
        ai_score=None,
        ai_summary=None,
        ai_recommendations=[],
        confidence=None,
        confidence_label=None,
        confidence_rationale=None,
        disposition=None,
        funnel_stage="ingested",
        affected_ips=[],
        affected_hosts=[],
        affected_users=[],
        case_id=None,
        tags=[],
        event_time=now,
        first_seen=now,
        last_seen=now,
        snoozed_until=None,
        snoozed_by_id=None,
        created_at=now,
        updated_at=now,
    )
    response = _to_alert_response(
        alert,  # type: ignore[arg-type]
        {connector_id: "Splunk SIEM 107 payload"},
    )
    assert response.connector_id == connector_id
    assert response.connector_name == "Splunk SIEM 107 payload"
    assert response.source == "Splunk SIEM 107 payload"
