"""Static packaging guardrails for the internal Gateway REST client."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_docker_fallback_installs_rest_runtime_without_external_sdk() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = pyproject["tool"]["poetry"]["dependencies"]

    assert '"httpx>=0.26,<0.29"' in dockerfile
    assert '"jsonschema>=4.21,<5"' in dockerfile
    assert dependencies["httpx"] == ">=0.26,<0.29"
    assert dependencies["jsonschema"] == ">=4.21,<5.0"
    assert "soorin-privacy-sdk" not in dependencies
    assert "soorin-privacy-sdk" not in dockerfile
    assert "soorin_privacy" not in dockerfile
    assert "from app.privacy.rest_client import PrivacyGatewayRESTClient" in dockerfile
    assert "COPY scripts/check_remote_privacy_gateway.py ./scripts/check_remote_privacy_gateway.py" in dockerfile
    assert "import opentelemetry" in dockerfile


def test_lockfile_contains_no_external_privacy_sdk() -> None:
    lockfile = (ROOT / "poetry.lock").read_text(encoding="utf-8")

    assert 'name = "soorin-privacy-sdk"' not in lockfile
    assert "Agent_Data_privacy_gateway" not in lockfile


def test_internal_rest_client_is_importable() -> None:
    from app.privacy.rest_client import PrivacyGatewayRESTClient

    assert PrivacyGatewayRESTClient.__name__ == "PrivacyGatewayRESTClient"
