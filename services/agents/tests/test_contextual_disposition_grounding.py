"""Ensure FP assessment respects analyst disposition when present."""

from __future__ import annotations

from app.api.contextual import ContextualActionRequest, _build_messages


def test_false_positive_prompt_includes_disposition_ground_truth():
    req = ContextualActionRequest(
        page="alerts",
        action="false_positive",
        entity_id="11111111-1111-1111-1111-111111111111",
        entity={
            "title": "Command Injection Attempts",
            "severity": "high",
            "disposition": "true_positive",
        },
    )
    system, user = _build_messages(req)
    assert "GROUND TRUTH" in system or "disposition is ground truth" in system.lower()
    assert "true_positive" in user
    assert "GROUND TRUTH" in user
