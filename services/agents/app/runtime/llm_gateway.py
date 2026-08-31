"""LLM gateway façade over the existing factory (spec §34). Does not replace LiteLLM."""

from __future__ import annotations

from typing import Any

from app.llm.factory import make_chat_model, resolve_base_url, resolve_model_alias


PROMPT_VERSION = "agentic-soc-runtime/v1"


class LLMGateway:
    """Single entry for runtime callers. Existing agents keep using factory.py."""

    prompt_version: str = PROMPT_VERSION

    def resolve_alias(self, role: str) -> str:
        return resolve_model_alias(role)

    def resolve_base_url(self) -> str | None:
        return resolve_base_url()

    def make_model(self, role: str, **kwargs: Any) -> Any:
        return make_chat_model(role, **kwargs)

    def metadata(self, role: str) -> dict[str, str]:
        return {
            "prompt_version": self.prompt_version,
            "role": role,
            "model_alias": self.resolve_alias(role),
        }
