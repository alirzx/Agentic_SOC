"""Static packaging guardrails for the independent Gateway SDK."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_docker_fallback_matches_gateway_sdk_runtime_constraints() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = pyproject["tool"]["poetry"]["dependencies"]
    sdk = dependencies["soorin-privacy-sdk"]

    assert '"httpx>=0.27,<0.29"' in dockerfile
    assert '"jsonschema>=4.21,<5"' in dockerfile
    assert dependencies["httpx"] == ">=0.26,<0.29"
    assert dependencies["jsonschema"] == ">=4.21,<5.0"
    assert f"@{sdk['rev']}#subdirectory={sdk['subdirectory']}" in dockerfile
    assert "import opentelemetry" in dockerfile and "soorin_privacy" in dockerfile


def test_sdk_pin_is_immutable_and_present_in_lockfile() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    sdk = pyproject["tool"]["poetry"]["dependencies"]["soorin-privacy-sdk"]
    lockfile = (ROOT / "poetry.lock").read_text(encoding="utf-8")

    assert re.fullmatch(r"[0-9a-f]{40}", sdk["rev"])
    assert f'resolved_reference = "{sdk["rev"]}"' in lockfile
