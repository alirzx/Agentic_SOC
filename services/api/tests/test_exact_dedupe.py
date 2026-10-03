"""Unit tests for exact alert/case dedupe helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.services.exact_dedupe import (
    alert_display_key,
    case_content_key,
    normalize_case_description,
    pick_canonical_alert,
    pick_canonical_case,
)


def test_agentic_case_key_ignores_primary_alert_uuid():
    a = case_content_key(
        title="ESCU - Access LSASS Memory for Dump Creation - Rule",
        severity="medium",
        description=(
            "Auto-created by Agentic SOC 24h funnel backfill.\n"
            "Disposition: true_positive\n"
            "Primary alert: 4db4a359-0e99-543f-b881-a9ff2143d3f9\n"
            "Linked alerts: 1\n"
        ),
        created_by="agentic-funnel-backfill",
    )
    b = case_content_key(
        title="ESCU - Access LSASS Memory for Dump Creation - Rule",
        severity="medium",
        description=(
            "Auto-created by Agentic SOC 24h funnel backfill.\n"
            "Disposition: true_positive\n"
            "Primary alert: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"
            "Linked alerts: 3\n"
        ),
        created_by="agentic-funnel-backfill",
    )
    assert a == b


def test_manual_cases_require_exact_description():
    a = case_content_key(
        title="Phish",
        severity="high",
        description="User reported phish",
        created_by="analyst@example.com",
    )
    b = case_content_key(
        title="Phish",
        severity="high",
        description="Different details",
        created_by="analyst@example.com",
    )
    assert a != b


def test_normalize_strips_agentic_noise():
    body = normalize_case_description(
        "Primary alert: 11111111-1111-1111-1111-111111111111 Linked alerts: 2 confidence=0.91",
        created_by="agentic-funnel",
    )
    assert "11111111" not in body
    assert "Linked alerts: N" in body
    assert "confidence=<n>" in body


def test_pick_canonical_case_prefers_richest_then_oldest():
    older = datetime(2026, 10, 1, tzinfo=UTC)
    newer = older + timedelta(hours=2)
    rich = {
        "id": uuid4(),
        "alert_ids": [uuid4(), uuid4()],
        "has_external_ref": False,
        "opened_at": newer,
    }
    poor_old = {
        "id": uuid4(),
        "alert_ids": [uuid4()],
        "has_external_ref": False,
        "opened_at": older,
    }
    assert pick_canonical_case([poor_old, rich])["id"] == rich["id"]


def test_pick_canonical_alert_prefers_cased():
    older = datetime(2026, 10, 1, tzinfo=UTC)
    a = {"id": uuid4(), "case_id": None, "created_at": older}
    b = {"id": uuid4(), "case_id": uuid4(), "created_at": older + timedelta(hours=1)}
    assert pick_canonical_alert([a, b])["id"] == b["id"]


def test_alert_display_key_ignores_source_event_ids():
    base = {
        "title": "ESCU - Access LSASS Memory for Dump Creation - Rule",
        "severity": "medium",
        "rule_id": "access_lsass_memory_for_dump_creation",
        "rule_name": "ESCU - Access LSASS Memory for Dump Creation - Rule",
        "disposition": "true_positive",
        "affected_hosts": [],
        "affected_ips": [],
        "affected_users": [],
    }
    a = {**base, "source_event_ids": ["evt-1"], "dedup_hash": "aaa"}
    b = {**base, "source_event_ids": ["evt-2"], "dedup_hash": "bbb"}
    assert alert_display_key(a) == alert_display_key(b)


def test_alert_display_key_keeps_different_hosts_apart():
    a = {
        "title": "ESCU - Access LSASS Memory for Dump Creation - Rule",
        "severity": "medium",
        "rule_id": "x",
        "disposition": "true_positive",
        "affected_hosts": ["host-a"],
        "affected_ips": [],
        "affected_users": [],
    }
    b = {**a, "affected_hosts": ["host-b"]}
    assert alert_display_key(a) != alert_display_key(b)
