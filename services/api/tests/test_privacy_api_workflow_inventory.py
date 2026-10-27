"""Static regression inventory for eight API-owned LLM entry points.

Does not exercise routes or real providers. Functional coverage requires
mocked endpoint tests and controlled live Gateway checks.
"""
from __future__ import annotations

from pathlib import Path

import pytest

API_ROOT = Path(__file__).resolve().parents[1] / "app"

@pytest.mark.parametrize("file_path", [
    "api/v1/endpoints/hunts.py",
    "api/v1/endpoints/translation.py",
    "api/v1/endpoints/knowledge_base.py",
    "api/v1/endpoints/phishing.py",
    "api/v1/endpoints/detection_loop.py",
    "api/v1/endpoints/nl_detection.py",
    "api/v1/endpoints/nl_query.py",
    "services/alert_explain.py",
])
def test_api_workflow_calls_privacy_boundary(file_path: str) -> None:
    content = (API_ROOT / file_path).read_text(encoding="utf-8")
    assert "safe_chat_post(" in content, file_path
    assert "from app.services.privacy_llm import" in content, file_path


def test_api_client_requires_explicit_tenant() -> None:
    content = (API_ROOT / "services/privacy_llm.py").read_text(encoding="utf-8")
    assert "tenant_id: str | uuid.UUID | None" in content
    assert "_tenant_uuid(tenant_id)" in content
