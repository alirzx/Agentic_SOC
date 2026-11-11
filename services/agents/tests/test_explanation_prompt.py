"""Unit tests for Investigate prompt appendix from Ambient Copilot explain."""

from __future__ import annotations

from app.investigator.explanation_prompt import format_explanation_guidance


def test_format_explanation_guidance_includes_steps():
    raw = {
        "contextual_explanation": {
            "meaning": "This is a detection-rule hit, not a confirmed compromise.",
            "markdown": "## What this alert means\n\nDetection-rule hit.",
            "suggested_next_steps": [
                "Pivot on the querying host",
                "Check EDR process tree",
            ],
        }
    }
    text = format_explanation_guidance(raw)
    assert "What this alert means" in text
    assert "Suggested next steps to pursue" in text
    assert "Pivot on the querying host" in text
    assert "<UNTRUSTED_DATA>" in text


def test_format_explanation_guidance_empty_without_explanation():
    assert format_explanation_guidance({}) == ""
    assert format_explanation_guidance(None) == ""
