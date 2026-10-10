"""Deployment definitions must pass privacy and trace controls into agents."""

from __future__ import annotations

from pathlib import Path


def test_agents_compose_definitions_propagate_privacy_environment() -> None:
    root = Path(__file__).resolve().parents[3]
    required = {
        "AISOC_LLM_PRIVACY_ENABLED: ${AISOC_LLM_PRIVACY_ENABLED:-0}",
        "AISOC_PRIVACY_TOKEN_KEY: ${AISOC_PRIVACY_TOKEN_KEY:-}",
        "AISOC_LLM_PRIVACY_STREAM_MAX_CHARS: ${AISOC_LLM_PRIVACY_STREAM_MAX_CHARS:-1000000}",
        "AISOC_LLM_HUMAN_TRACE_ENABLED: ${AISOC_LLM_HUMAN_TRACE_ENABLED:-0}",
        "AISOC_LLM_HUMAN_TRACE_MAX_CHARS: ${AISOC_LLM_HUMAN_TRACE_MAX_CHARS:-50000}",
        "AISOC_AGENTS_TENANT_SIGNING_KEY: ${AISOC_AGENTS_TENANT_SIGNING_KEY:-}",
    }
    for relative in ("docker-compose.yml", "infra/compose/docker-compose.demo.yml"):
        text = (root / relative).read_text(encoding="utf-8")
        missing = required - set(text.splitlines())
        # Ignore YAML indentation when comparing the exact assignments.
        if missing:
            stripped = {line.strip() for line in text.splitlines()}
            missing = required - stripped
        assert not missing, f"{relative} is missing agents privacy env: {sorted(missing)}"


def test_env_example_documents_default_off_human_trace() -> None:
    root = Path(__file__).resolve().parents[3]
    text = (root / ".env.example").read_text(encoding="utf-8")
    assert "AISOC_LLM_HUMAN_TRACE_ENABLED=0" in text
    assert "AISOC_LLM_HUMAN_TRACE_MAX_CHARS=50000" in text
