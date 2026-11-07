"""Tests for automation-rule authoring: search-free preview, real ceilings.

Three fields in the rule editor were stored but never read, which made the form
decorative. These tests pin the fixes:

1. the draft preview runs unsaved rules through the real evaluator and gate,
2. a rule's autonomy ceiling actually caps the policy decision,
3. `subject_type` is enforced in the rule query, not just displayed,
4. preview and live execution evaluate the same subject dict.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.runbook import (
    RuleDraftPreviewRequest,
    preview_automation_rule_draft,
)
from app.services.runbook.rule_executor import (
    _FETCH_RULES,
    alert_subject_fields,
    apply_rule_autonomy_ceiling,
)
from app.services.runbook.thresholds import AutonomyDecision, make_thresholds

# ── helpers ──────────────────────────────────────────────────────────────────


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
        "title": "Correlated sign-in anomaly",
        "severity": "critical",
        "status": "new",
        "priority": 90,
        "confidence": 95,
        "confidence_label": "high",
        "funnel_stage": "triaged",
        "disposition": None,
        "source": "identity",
        "connector_type": "okta",
        "category": "identity",
        "description": "impossible travel",
        "tags": ["travel"],
        "affected_ips": ["10.0.0.9"],
        "affected_hosts": [],
        "affected_users": ["alice"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1078"],
        "rule_name": "Impossible travel",
        "created_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(row, key, value)
    return row


def _gate(**overrides: Any) -> Any:
    from app.services.runbook.gate import GateDecision

    fields = {
        "action": "close_alert",
        "decision": AutonomyDecision.AUTO,
        "allowed": True,
        "approval_required": False,
        "autonomy_level": "L4",
        "layer": "defaults",
        "thresholds": make_thresholds(0.5, 0.7, 0.9),
        "reason": "confidence_above_auto_threshold",
        "definition": None,
    }
    fields.update(overrides)
    return GateDecision(**fields)


# ── the ceiling is really read ───────────────────────────────────────────────


def test_rule_ceiling_turns_autonomy_into_approval_not_refusal() -> None:
    """A rule capped at L1 must wait for a human, not be recorded as denied."""
    capped = apply_rule_autonomy_ceiling(_gate(autonomy_level="L4"), "L1")

    assert capped.allowed is True  # policy still permits it
    assert capped.approval_required is True
    assert capped.autonomy_level == "L1"
    assert capped.decision is AutonomyDecision.REVIEW
    assert "rule_ceiling" in capped.layer
    assert "L1" in capped.reason and "L4" in capped.reason


def test_rule_ceiling_never_loosens_a_stricter_policy() -> None:
    original = _gate(allowed=False, approval_required=True, autonomy_level="L0")
    assert apply_rule_autonomy_ceiling(original, "L4") == original


def test_rule_without_a_ceiling_is_untouched() -> None:
    original = _gate()
    assert apply_rule_autonomy_ceiling(original, None) == original


# ── subject_type is enforced, not displayed ─────────────────────────────────


def test_rule_query_filters_on_subject_type() -> None:
    sql = re.sub(r"\s+", " ", str(_FETCH_RULES)).lower()
    assert "subject_type = :subject_type" in sql
    # NULL/'all' stay catch-all so rules written before the column keep working.
    assert "subject_type is null" in sql
    assert "subject_type = 'all'" in sql


# ── preview / live parity ───────────────────────────────────────────────────


def test_subject_fields_include_everything_the_preview_offers() -> None:
    """A field offered in the editor must exist in the dict the executor builds."""
    fields = alert_subject_fields(_alert())

    for key in (
        "severity",
        "status",
        "confidence",
        "disposition",
        "source",
        "rule_name",
        "mitre_techniques",
        "affected_users",
        "tags",
    ):
        assert key in fields


# ── draft preview ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_draft_preview_uses_the_real_gate_and_ceiling() -> None:
    user = _user()
    db = MagicMock()
    db.execute = AsyncMock(
        return_value=MagicMock(
            scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[_alert()])))
        )
    )

    body = RuleDraftPreviewRequest(
        conditions=[{"field": "severity", "op": "eq", "value": "critical"}],
        action_slug="close_alert",
        autonomy_level="L0",
        dry_run=True,
    )

    result = await preview_automation_rule_draft(body=body, db=db, current_user=user)

    assert result.evaluated == 1
    assert result.matched == 1
    # The policy would allow this outright; the rule's L0 ceiling holds it.
    assert result.matches[0].status == "recorded"
    assert "ceiling" in (result.matches[0].reason or "").lower()


@pytest.mark.asyncio
async def test_draft_preview_is_tenant_scoped() -> None:
    user = _user()
    db = MagicMock()
    db.execute = AsyncMock(
        return_value=MagicMock(
            scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        )
    )

    await preview_automation_rule_draft(
        body=RuleDraftPreviewRequest(action_slug="close_alert"),
        db=db,
        current_user=user,
    )

    compiled = db.execute.call_args.args[0]
    assert user.tenant_id in set(compiled.compile().params.values())


@pytest.mark.asyncio
async def test_draft_preview_reports_invalid_conditions_instead_of_matching_nothing() -> None:
    """An unknown operator must be an error, not a silent 'no matches'."""
    user = _user()
    db = MagicMock()
    db.execute = AsyncMock()

    result = await preview_automation_rule_draft(
        body=RuleDraftPreviewRequest(
            conditions=[{"field": "severity", "op": "regex_matches", "value": "^crit"}],
            action_slug="close_alert",
        ),
        db=db,
        current_user=user,
    )

    assert result.errors
    assert result.evaluated == 0
    db.execute.assert_not_called()
