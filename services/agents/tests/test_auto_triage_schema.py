"""Schema validation for Tier-1 LLM triage output."""

from __future__ import annotations

import pytest
from app.agents.auto_triage_agent import AutoTriageError, TriageVerdictSchema, _parse_llm_response


def test_valid_schema_parses():
    out = _parse_llm_response(
        '{"verdict":"false_positive","confidence":0.91,"rationale":"Known scanner window."}'
    )
    assert out["verdict"] == "false_positive"
    assert out["confidence"] == 0.91


def test_markdown_fenced_json_parses():
    text = """```json
{"verdict": "needs_review", "confidence": 0.4, "rationale": "Missing auth logs"}
```"""
    out = _parse_llm_response(text)
    assert out["verdict"] == "needs_review"


def test_malformed_json_raises():
    with pytest.raises(AutoTriageError):
        _parse_llm_response("not json at all")


def test_schema_rejects_confidence_out_of_range():
    with pytest.raises(AutoTriageError):
        _parse_llm_response('{"verdict":"true_positive","confidence":2.5,"rationale":"x"}')


def test_unknown_verdict_normalized_to_true_positive():
    model = TriageVerdictSchema.model_validate(
        {"verdict": "totally_unknown", "confidence": 0.5, "rationale": "fallback"}
    )
    assert model.verdict == "true_positive"
