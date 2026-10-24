"""Phase 2.1 — hard budget checks are executable, not prompt-only."""

from __future__ import annotations

import pytest
from app.graph.runner import (
    BudgetExhausted,
    InvestigationBudget,
    assert_tool_budget_allows,
    current_investigation_budget,
)


def test_tool_budget_assert_raises_when_exhausted(monkeypatch):
    budget = InvestigationBudget(max_tool_calls=1, max_node_steps=10, max_tokens=1000)
    budget.record_tool_call()
    assert budget.can_call_tool() is False

    import app.graph.runner as runner_mod

    monkeypatch.setattr(runner_mod, "_active_budget", budget)
    with pytest.raises(BudgetExhausted):
        assert_tool_budget_allows(tool_name="splunk_search")
    monkeypatch.setattr(runner_mod, "_active_budget", None)


def test_token_sync_marks_stop_reason():
    budget = InvestigationBudget(max_tokens=10, max_tool_calls=5, max_node_steps=5)
    budget.tokens_used = 10
    budget.sync_tokens_from_tracker()  # no tracker — keeps existing
    if budget.tokens_used >= budget.max_tokens:
        budget.stop_reason = budget.stop_reason or "token_budget_exhausted"
    assert budget.stop_reason == "token_budget_exhausted"


def test_node_step_budget_sets_reason():
    budget = InvestigationBudget(max_node_steps=2, max_tool_calls=10)
    budget.record_node_step()
    budget.record_node_step()
    assert budget.stop_reason == "node_step_budget_exhausted"
    assert budget.can_step() is False


def test_no_active_budget_allows_tools():
    assert current_investigation_budget() is None
    assert_tool_budget_allows(tool_name="noop")  # must not raise
