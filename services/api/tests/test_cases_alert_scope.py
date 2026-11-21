"""Correlation scope helpers used by the candidate and case endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app.api.v1.endpoints.cases import (
    CandidateScopeEcho,
    ScopeDrop,
    _detail_model,
    _empty_component,
    _parse_scope_request,
)
from fastapi import HTTPException


def test_parse_scope_request_splits_ids_and_validates_filters() -> None:
    excluded, filters = _parse_scope_request(
        " a1 , a2 ,,", ["llm_payload.alert_fields.index|eq|vulnscan|exclude"]
    )
    assert excluded == ["a1", "a2"]
    assert filters == ["llm_payload.alert_fields.index|eq|vulnscan|exclude"]


def test_parse_scope_request_rejects_fields_outside_the_payload() -> None:
    with pytest.raises(HTTPException) as exc:
        _parse_scope_request(None, ["affected_hosts|eq|win-dc-01|exclude"])
    assert exc.value.status_code == 422
    assert exc.value.detail["error"] == "invalid_scope_filter"


def test_parse_scope_request_with_no_parameters() -> None:
    assert _parse_scope_request(None, None) == ([], [])


def test_empty_component_keeps_the_candidate_identity() -> None:
    component = _empty_component(
        {"candidate_key": "component-abc", "campaign_theme": "APT_ACTIVITY", "severity": "high"},
        [],
    )
    assert component["candidate_key"] == "component-abc"
    assert component["campaign_theme"] == "APT_ACTIVITY"
    assert component["alert_count"] == 0
    assert component["graph"]["nodes"] == []
    assert component["score_breakdown"]["peak_score"] == 0


def test_detail_model_carries_the_scope_echo() -> None:
    now = datetime.now(UTC)
    dropped = ScopeDrop(alert_id="a1", title="Noisy scan", reason="excluded by the analyst")
    echo = CandidateScopeEcho(
        excluded_alert_ids=["a1"],
        filters=[],
        dropped=[dropped],
        available_alert_count=3,
    )
    model = _detail_model(
        {
            "score": 5,
            "alert_count": 2,
            "alert_ids": ["b1", "b2"],
            "entities": {"hosts": ["win-dc-01"]},
            "techniques": ["T1003"],
            "time_first": now,
            "time_last": now,
            "severity": "high",
        },
        candidate_key="case:123",
        campaign_theme="Case title",
        scope=echo,
    )
    assert model.candidate_key == "case:123"
    assert model.campaign_theme == "Case title"
    assert model.entity_summary["hosts"] == 1
    assert model.scope is not None
    assert model.scope.dropped[0].alert_id == "a1"


def test_empty_component_is_serialisable() -> None:
    """A case whose evidence no longer scores must still return 200.

    Regression: ``CandidateDetail.score`` required ``>= 1``, so the empty
    component built by ``_empty_component`` raised a pydantic ``ValidationError``
    and ``GET /cases/{id}/correlation`` answered 500 instead of an empty graph.
    """

    now = datetime.now(UTC)
    component = _empty_component(
        {"candidate_key": "case:abc", "campaign_theme": "CASE_EVIDENCE"},
        ["a1", "a2"],
    )
    model = _detail_model(
        {**component, "score": component["score"], "time_first": now, "time_last": now},
        candidate_key="case:abc",
        campaign_theme="CASE_EVIDENCE",
        scope=None,
    )
    assert model.score == 0
    assert model.alert_count == 2
    assert model.graph is not None and model.graph.nodes == []
