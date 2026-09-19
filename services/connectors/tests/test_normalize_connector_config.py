"""Regression: corrupted connector_config array from checkpoint writes."""

from __future__ import annotations

from app.db.connector_repo import normalize_connector_config


def test_normalize_plain_dict() -> None:
    actual = normalize_connector_config({"poll_interval_seconds": 1800})
    assert actual == {"poll_interval_seconds": 1800}


def test_normalize_nullish() -> None:
    assert normalize_connector_config(None) == {}
    assert normalize_connector_config(42) == {}


def test_normalize_corrupt_array_with_stringified_checkpoint() -> None:
    """Matches the production failure shape from asyncpg double-encode."""
    corrupt = [
        {
            "base_url": "https://192.168.0.10:8089",
            "poll_interval_seconds": 1800,
            "ssl_verify": False,
        },
        '{"checkpoint": {"time": "2026-07-01T12:48:35.000+03:30", '
        '"id": "af145ac9-6b34-49b9-af4a-afe5e342e47c"}}',
    ]
    actual = normalize_connector_config(corrupt)
    assert actual["poll_interval_seconds"] == 1800
    assert actual["base_url"] == "https://192.168.0.10:8089"
    assert actual["checkpoint"]["id"] == "af145ac9-6b34-49b9-af4a-afe5e342e47c"


def test_normalize_json_string() -> None:
    actual = normalize_connector_config('{"earliest_time": "-90d@d"}')
    assert actual == {"earliest_time": "-90d@d"}
