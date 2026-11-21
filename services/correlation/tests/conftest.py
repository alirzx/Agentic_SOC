"""Shared fixtures for the correlation engine test suite.

``fixtures/alerts_2026_11_08.json`` is the real 166-notable corpus captured from
the lab Splunk instance on 2026-11-08 (`docs/plans/case/1794160586_1975.json`),
reduced to the ``llm_payload`` field — the single source of truth the engine is
allowed to read. Keeping the real payloads (rather than hand-written minimal
dicts) is what makes these tests able to catch vendor-shape regressions.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "alerts_2026_11_08.json"


@pytest.fixture(scope="session")
def corpus() -> list[dict[str, Any]]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def by_rule(corpus: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for payload in corpus:
        grouped[payload["rule_name"]].append(payload)
    return dict(grouped)
