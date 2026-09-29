"""Unit tests for agentic case promotion policy."""

from __future__ import annotations

from app.workers.case_promoter import should_promote


def test_true_positive_always_promotes():
    assert should_promote(verdict="true_positive", severity="low", confidence=0.4) is True
    assert should_promote(verdict="true_positive", severity="critical", confidence=0.9) is True


def test_false_positive_never_promotes():
    assert should_promote(verdict="false_positive", severity="critical", confidence=0.99) is False
    assert should_promote(verdict="benign_true_positive", severity="high", confidence=0.9) is False


def test_needs_review_promotes_high_or_confident_medium():
    assert should_promote(verdict="needs_review", severity="high", confidence=0.2) is True
    assert should_promote(verdict="needs_review", severity="medium", confidence=0.7) is True
    assert should_promote(verdict="needs_review", severity="medium", confidence=0.2) is False
    assert should_promote(verdict="needs_review", severity="low", confidence=0.9) is False
