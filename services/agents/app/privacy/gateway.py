"""Message/JSON projection and exact response restoration at LLM egress."""

from __future__ import annotations

import copy
import hashlib
import hmac
from typing import Any

from app.privacy.redactor import Pseudonymizer


class PrivacyGateway:
    policy_version = "v1"

    def __init__(self, *, tenant_id: str, token_key: str | bytes) -> None:
        key = token_key.encode() if isinstance(token_key, str) else bytes(token_key)
        self.codec = Pseudonymizer(tenant_id=tenant_id, token_key=key)
        self.tenant_id = tenant_id
        self.cache_namespace = "privacy:v1:" + hmac.new(key, b"cache\x00" + tenant_id.encode(), hashlib.sha256).hexdigest()

    def project_messages(self, messages: list[Any]) -> list[Any]:
        return [self._transform_message(message, project=True) for message in messages]

    def project_value(self, value: Any) -> Any:
        return self.codec.redact_value(value)

    def process_response(self, response: Any) -> Any:
        return self._transform_message(response, project=False)

    def _transform_message(self, value: Any, *, project: bool) -> Any:
        transform = self.codec.redact_value if project else self.codec.rehydrate
        if isinstance(value, (str, dict, list)):
            return transform(value)
        if isinstance(value, tuple):
            if len(value) == 2 and isinstance(value[0], str):
                return (value[0], transform(value[1]))
            return tuple(transform(list(value)))
        updates: dict[str, Any] = {}
        for attribute in ("content", "additional_kwargs", "tool_calls", "invalid_tool_calls"):
            if hasattr(value, attribute):
                updates[attribute] = transform(getattr(value, attribute))
        if not updates:
            return transform(value)
        if hasattr(value, "model_copy"):
            return value.model_copy(update=updates, deep=True)
        cloned = copy.copy(value)
        for attribute, transformed in updates.items():
            try:
                setattr(cloned, attribute, transformed)
            except (AttributeError, TypeError):
                pass
        return cloned
