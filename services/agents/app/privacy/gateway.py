"""Message/JSON projection and exact response restoration at LLM egress."""

from __future__ import annotations

import copy
import hashlib
import hmac
from typing import Any

from app.privacy.redactor import Pseudonymizer

PRIVACY_SYSTEM_GUIDANCE = (
    "Some internal SOC identities in this request have been replaced with privacy-preserving "
    "pseudonyms such as USER_*, EMAIL_*, HOST_*, ASSET_*, IP_V4_*, IP_V6_*, IP_OPAQUE_*, and PATH_*.\n\n"
    "Treat each pseudonym as an opaque but stable identity within this analysis. Preserve every "
    "pseudonym exactly when referring to it or passing it to tools. Do not decode, guess, reconstruct, "
    "abbreviate, truncate, or infer the original identity. Do not treat pseudonym syntax itself as "
    "evidence of maliciousness.\n\n"
    "[REDACTED_SECRET] means a secret was intentionally withheld. Do not guess or reconstruct it. "
    "Reason using relationships, behavior, security evidence, MITRE techniques, scores, and other supplied context."
)


class PrivacyGateway:
    policy_version = "v1.1"

    def __init__(self, *, tenant_id: str, token_key: str | bytes) -> None:
        key = token_key.encode() if isinstance(token_key, str) else bytes(token_key)
        self.codec = Pseudonymizer(tenant_id=tenant_id, token_key=key)
        self.tenant_id = tenant_id
        self.cache_namespace = "privacy:v1.1:" + hmac.new(
            key,
            b"cache:v1.1\x00" + tenant_id.encode(),
            hashlib.sha256,
        ).hexdigest()

    def project_messages(self, messages: list[Any]) -> list[Any]:
        # Discover across the whole turn before projecting any individual
        # message so aliases do not depend on message or dictionary order.
        for message in messages:
            self.codec.discover_value(self._message_value(message))
        projected = [self._transform_message(message, project=True) for message in messages]
        return [self._guidance_message(projected), *projected]

    def project_value(self, value: Any) -> Any:
        return self.codec.redact_value(value)

    def process_response(self, response: Any) -> Any:
        return self._transform_message(response, project=False)

    @staticmethod
    def _message_value(value: Any) -> Any:
        if isinstance(value, (str, dict, list, tuple)):
            return value
        return {
            attribute: getattr(value, attribute)
            for attribute in ("content", "additional_kwargs", "tool_calls", "invalid_tool_calls")
            if hasattr(value, attribute)
        }

    @staticmethod
    def _guidance_message(messages: list[Any]) -> Any:
        if messages and isinstance(messages[0], dict):
            return {"role": "system", "content": PRIVACY_SYSTEM_GUIDANCE}
        if messages and isinstance(messages[0], tuple):
            return ("system", PRIVACY_SYSTEM_GUIDANCE)
        from langchain_core.messages import SystemMessage

        return SystemMessage(content=PRIVACY_SYSTEM_GUIDANCE)

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
