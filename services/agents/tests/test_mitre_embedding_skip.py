"""Tests for ATT&CK embedding skip logic (chat-only gateways)."""

from __future__ import annotations

from app.tools.mitre_full import _embedding_skip_reason


def test_skip_when_flag_set(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_SKIP_EMBEDDINGS", "1")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("AISOC_EMBEDDING_BASE_URL", raising=False)
    assert _embedding_skip_reason() is not None


def test_skip_arvan_chat_gateway_without_embed_base(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_SKIP_EMBEDDINGS", raising=False)
    monkeypatch.setenv(
        "OPENAI_BASE_URL",
        "https://arvancloudai.ir/gateway/models/DeepSeek-V4-Flash/token/v1",
    )
    monkeypatch.delenv("AISOC_EMBEDDING_BASE_URL", raising=False)
    reason = _embedding_skip_reason()
    assert reason is not None
    assert "chat-only" in reason.lower() or "Arvan" in reason


def test_allow_when_dedicated_embedding_base(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_SKIP_EMBEDDINGS", raising=False)
    monkeypatch.setenv(
        "OPENAI_BASE_URL",
        "https://arvancloudai.ir/gateway/models/DeepSeek-V4-Flash/token/v1",
    )
    monkeypatch.setenv("AISOC_EMBEDDING_BASE_URL", "https://api.openai.com/v1")
    assert _embedding_skip_reason() is None


def test_allow_when_no_chat_base(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_SKIP_EMBEDDINGS", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("AISOC_EMBEDDING_BASE_URL", raising=False)
    assert _embedding_skip_reason() is None
