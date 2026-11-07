"""Tests for the Detect & Fuse view (Workflow SOC stage 02).

The stage claims rules and correlation turn noise into alerts. These tests pin
the two things that could quietly turn that claim into decoration:

1. the shaping is read from persisted columns, never inferred, and
2. the summary describes the rows on screen rather than a made-up total.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.runbook import runbook_detection_activity
from app.services.runbook.detections import (
    fusion_state_for,
    item_from_alert,
    summarize,
)


def _user() -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="soc_analyst",
        email="analyst@example.com",
    )


def _alert(**overrides: Any) -> MagicMock:
    row = MagicMock()
    defaults = {
        "id": uuid.uuid4(),
        "title": "Credential dumping on FIN-WS-04",
        "severity": "high",
        "created_at": datetime.now(UTC),
        "rule_id": "splunk-rule-9901",
        "rule_name": "Mimikatz string match",
        "connector_type": "splunk",
        "confidence": 78,
        "occurrence_count": 1,
        "is_merged": False,
        "fusion_incident_id": None,
        "parent_alert_id": None,
    }
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(row, key, value)
    return row


# ── fusion classification ────────────────────────────────────────────────────


def test_incident_outranks_merged() -> None:
    """An alert in a windowed incident is the more useful fact to show."""
    assert (
        fusion_state_for(
            fusion_incident_id=uuid.uuid4(),
            is_merged=True,
            parent_alert_id=uuid.uuid4(),
        )
        == "incident"
    )


def test_merged_when_correlated_without_an_incident() -> None:
    assert (
        fusion_state_for(fusion_incident_id=None, is_merged=False, parent_alert_id=uuid.uuid4())
        == "merged"
    )
    assert (
        fusion_state_for(fusion_incident_id=None, is_merged=True, parent_alert_id=None)
        == "merged"
    )


def test_standalone_otherwise() -> None:
    assert (
        fusion_state_for(fusion_incident_id=None, is_merged=False, parent_alert_id=None)
        == "standalone"
    )


# ── shaping ──────────────────────────────────────────────────────────────────


def test_item_reads_rule_and_source_from_columns() -> None:
    row = _alert(occurrence_count=3)
    item = item_from_alert(row)

    assert item.alert_id == row.id
    assert item.rule_id == "splunk-rule-9901"
    assert item.rule_name == "Mimikatz string match"
    assert item.connector_type == "splunk"
    assert item.occurrence_count == 3
    assert item.has_rule is True


def test_item_reports_a_missing_rule_instead_of_guessing_one() -> None:
    """No rule recorded is a fact worth showing; a title is not a rule name."""
    item = item_from_alert(_alert(rule_id=None, rule_name=None, connector_type=None))

    assert item.has_rule is False
    assert item.rule_name is None
    assert item.connector_type is None


def test_occurrence_count_falls_back_to_one() -> None:
    """Legacy rows can carry NULL; ×0 or ×None would both be wrong."""
    assert item_from_alert(_alert(occurrence_count=None)).occurrence_count == 1


# ── summary ──────────────────────────────────────────────────────────────────


def test_summary_counts_only_the_rows_it_was_given() -> None:
    items = [
        item_from_alert(_alert(rule_id="r1", rule_name="one", occurrence_count=1)),
        item_from_alert(_alert(rule_id="r1", rule_name="one", occurrence_count=4)),
        item_from_alert(_alert(rule_id=None, rule_name=None)),
        item_from_alert(_alert(fusion_incident_id=uuid.uuid4())),
        item_from_alert(_alert(is_merged=True)),
    ]

    summary = summarize(items)

    assert summary.examined == 5
    # r1 appears twice but is one rule; the row with no rule is not a rule.
    assert summary.distinct_rules == 2
    assert summary.without_rule == 1
    assert summary.incident_linked == 1
    assert summary.merged == 1
    assert summary.deduplicated == 1


def test_summary_keys_rules_on_id_not_on_display_name() -> None:
    """Two rules that share a display name are still two rules."""
    items = [
        item_from_alert(_alert(rule_id="r1", rule_name="Suspicious PowerShell")),
        item_from_alert(_alert(rule_id="r2", rule_name="Suspicious PowerShell")),
    ]

    assert summarize(items).distinct_rules == 2


def test_summary_of_nothing_is_zero_not_an_error() -> None:
    summary = summarize([])

    assert summary.examined == 0
    assert summary.distinct_rules == 0


# ── endpoint ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_activity_is_tenant_scoped_and_ordered_recent_first() -> None:
    user = _user()
    db = MagicMock()
    db.execute = AsyncMock(
        return_value=MagicMock(
            scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[_alert()])))
        )
    )

    result = await runbook_detection_activity(db=db, current_user=user, limit=25)

    compiled = db.execute.call_args.args[0]
    sql = re.sub(r"\s+", " ", str(compiled)).lower()
    # Tenant isolation lives in the WHERE clause, not only in RLS.
    assert "tenant_id" in sql
    assert "order by" in sql and "desc" in sql
    bound = set(compiled.compile().params.values())
    assert user.tenant_id in bound
    assert 25 in bound
    assert result.summary.examined == 1
    assert result.items[0].rule_name == "Mimikatz string match"
