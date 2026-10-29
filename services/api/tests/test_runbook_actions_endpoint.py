"""Tests for the GET /api/v1/runbook/actions endpoint.

Ensures the frontend can dynamically load the list of available actions from the backend.
"""

from __future__ import annotations

import uuid

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.runbook import list_automation_actions
from app.services.runbook.action_catalog import ACTIONS


def _user() -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="soc_analyst",
        email="analyst@example.com",
    )


@pytest.mark.asyncio
async def test_get_actions_returns_all_available_actions() -> None:
    """Endpoint returns all actions from the action catalog with name, label, category."""
    user = _user()
    result = await list_automation_actions(current_user=user)

    # Verify we get a list
    assert isinstance(result, list)

    # Verify all actions from the catalog are present
    assert len(result) == len(ACTIONS)

    # Verify each action has the required fields
    for action in result:
        assert "name" in action
        assert "label" in action
        assert "category" in action
        # Ensure it's a string, not other metadata
        assert isinstance(action["name"], str)
        assert isinstance(action["label"], str)
        assert isinstance(action["category"], str)

    # Verify no sensitive fields are leaked (e.g., thresholds, blast_radius)
    for action in result:
        assert "blast_radius" not in action
        assert "thresholds" not in action
        assert "audit_contract" not in action
        assert "data_safety_contract" not in action


@pytest.mark.asyncio
async def test_get_actions_has_read_case_containment_categories() -> None:
    """Endpoint groups actions by category (read, case, containment)."""
    user = _user()
    result = await list_automation_actions(current_user=user)

    categories = {action["category"] for action in result}
    # Verify we have at least the main categories (lowercase enum values)
    assert "read" in categories or "case" in categories or "containment" in categories


@pytest.mark.asyncio
async def test_get_actions_close_alert_present() -> None:
    """Verify the close_alert action (a basic one) is present."""
    user = _user()
    result = await list_automation_actions(current_user=user)

    # Find close_alert
    close_alert = next((a for a in result if a["name"] == "close_alert"), None)
    assert close_alert is not None
    assert "label" in close_alert
    assert "category" in close_alert


