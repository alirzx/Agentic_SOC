"""Unit tests for exact alert/case dedupe helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from app.services.exact_dedupe import (
    _mark_alerts_deduplicated,
    alert_display_key,
    case_content_key,
    merge_alert_entities,
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


def test_alert_display_key_collapses_same_rule_across_hosts():
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
    assert alert_display_key(a) == alert_display_key(b)


def test_merge_alert_entities_unions_hosts():
    rows = [
        {"affected_hosts": ["Host-A"], "affected_ips": ["1.1.1.1"], "affected_users": []},
        {"affected_hosts": ["host-a", "Host-B"], "affected_ips": [], "affected_users": ["alice"]},
    ]
    merged = merge_alert_entities(rows)
    assert merged["affected_hosts"] == ["Host-A", "Host-B"]
    assert merged["affected_ips"] == ["1.1.1.1"]
    assert merged["affected_users"] == ["alice"]


class _MappingResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def mappings(self):
        return self

    def all(self) -> list[dict[str, object]]:
        return self._rows


class _ExactDedupeDb:
    def __init__(self, loser_rows: list[dict[str, object]]) -> None:
        self.loser_rows = loser_rows
        self.statements: list[str] = []

    async def execute(self, statement):
        sql = str(statement)
        self.statements.append(sql)
        if "SELECT id, case_id FROM alerts" in sql:
            return _MappingResult(self.loser_rows)
        return _MappingResult([])


@pytest.mark.asyncio
async def test_legacy_dedup_preserves_cased_losers_and_clears_uncased_losers():
    uncased_id = uuid4()
    cased_id = uuid4()
    cased_case_id = uuid4()
    db = _ExactDedupeDb(
        [
            {"id": uncased_id, "case_id": None},
            {"id": cased_id, "case_id": cased_case_id},
        ]
    )

    await _mark_alerts_deduplicated(
        db,
        tenant_id=uuid4(),
        loser_ids=[uncased_id, cased_id],
        canonical_id=uuid4(),
        preserve_case_membership=False,
    )

    funnel_updates = [
        sql
        for sql in db.statements
        if "UPDATE alerts" in sql and "SET funnel_stage = 'deduplicated'" in sql
    ]
    assert len(funnel_updates) == 2
    assert any("case_id = NULL" in sql for sql in funnel_updates)
    assert any("case_id = NULL" not in sql for sql in funnel_updates)
    assert any("UPDATE aisoc_cases" in sql for sql in db.statements)
