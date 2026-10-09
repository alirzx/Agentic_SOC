"""Shared agents-test fixtures.

Wave 1 introduced two process-wide singletons that carry state across calls:
the CostGovernor (verdict dedup cache + per-tenant spend) and the LLM
ResponseCache. Reset both before every test so a verdict/response recorded by
one test can't leak into the next (e.g. a reused alert hitting DEDUPLICATED, or
a cached LLM response shadowing a test's mocked one).
"""

from __future__ import annotations

import pytest

SYNTHETIC_PRIVACY_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def privacy_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make a privacy-off test independent from the invoking shell."""
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "0")
    monkeypatch.delenv("AISOC_PRIVACY_TOKEN_KEY", raising=False)


@pytest.fixture
def privacy_enabled(monkeypatch: pytest.MonkeyPatch) -> str:
    """Enable privacy with a synthetic key for a single test."""
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", SYNTHETIC_PRIVACY_KEY)
    return SYNTHETIC_PRIVACY_KEY


@pytest.fixture(autouse=True)
def _reset_agent_singletons():
    from app.core.cost_governor import reset_governor
    from app.llm.contract import _RESPONSE_CACHE

    reset_governor()
    _RESPONSE_CACHE.clear()
    yield
    reset_governor()
    _RESPONSE_CACHE.clear()
