"""Contract-shape tests for the non-provider Gateway smoke utility."""

from __future__ import annotations

import pytest
from scripts.check_remote_privacy_gateway import _available_policy_names


def test_policy_parser_accepts_gateway_object_entries() -> None:
    assert _available_policy_names(
        {"policies": [{"name": "agentic-soc-v1", "version": "1.0.0"}]}
    ) == {"agentic-soc-v1"}


def test_policy_parser_reports_missing_profile_without_misreading_objects() -> None:
    names = _available_policy_names({"policies": [{"name": "generic-v1", "version": "1.0.0"}]})
    assert "agentic-soc-v1" not in names


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"policies": "agentic-soc-v1"},
        {"policies": ["agentic-soc-v1"]},
        {"policies": [{"name": "agentic-soc-v1"}]},
    ],
)
def test_policy_parser_rejects_malformed_gateway_responses(payload: dict) -> None:
    with pytest.raises(RuntimeError):
        _available_policy_names(payload)
