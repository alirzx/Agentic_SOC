"""Synthetic remote Gateway used by SOC adapter tests (no provider/network)."""

from __future__ import annotations

import copy
import re
from datetime import UTC, datetime, timedelta
from typing import Any


class SyntheticGatewayError(RuntimeError):
    def __init__(self, status_code: int) -> None:
        super().__init__("synthetic gateway failure")
        self.status_code = status_code


class FakePrivacyClient:
    def __init__(self, *, fail: str | None = None, fail_status: int = 503) -> None:
        self.fail = fail
        self.fail_status = fail_status
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.closed = False
        self.deleted = False
        self.context_id = "ctx_synthetic_remote"
        self.mapping = {
            "10.20.3.7": "IP_V4_PRIVATE_" + "A" * 32,
            "dc01.corp.example": "HOST_" + "B" * 32,
            "CORP\\alice": "USER_" + "C" * 32,
            "CORP\\svc-maint": "USER_" + "D" * 32,
            "C:\\Windows\\System32\\reg.exe": "PATH_" + "E" * 32,
        }

    def _maybe_fail(self, operation: str) -> None:
        if self.fail == operation:
            raise SyntheticGatewayError(self.fail_status)

    async def create_context(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("create_context", copy.deepcopy(kwargs)))
        self._maybe_fail("create_context")
        return {
            "context_id": self.context_id,
            "tenant_id": kwargs["tenant_id"],
            "profile": kwargs["profile"],
            "policy_version": "1.0.0",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        }

    async def encode(self, payload: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("encode", {"payload": copy.deepcopy(payload), **copy.deepcopy(kwargs)}))
        self._maybe_fail("encode")
        protected = self._walk(payload, encode=True)
        return {
            "context_id": self.context_id,
            "policy_version": "1.0.0",
            "format": kwargs["format"],
            "payload": protected,
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "stats": {"tokenized_unique": 5, "mapping_entries": 5, "credential_aliases": 0},
        }

    async def decode(self, payload: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("decode", {"payload": copy.deepcopy(payload), **copy.deepcopy(kwargs)}))
        self._maybe_fail("decode")
        unknown = 0
        known = set(self.mapping.values())
        token_re = re.compile(
            r"(?<![A-Za-z0-9_])(?:HOST|USER|PATH|IP_V4_PRIVATE|CRED_PASSWORD)_[A-F0-9]{24,40}(?![A-Za-z0-9_])"
        )

        def count_unknown(value: Any) -> None:
            nonlocal unknown
            if isinstance(value, str):
                unknown += sum(1 for match in token_re.finditer(value) if match.group() not in known)
            elif isinstance(value, dict):
                for child in value.values():
                    count_unknown(child)
            elif isinstance(value, list):
                for child in value:
                    count_unknown(child)

        count_unknown(payload)
        restored = self._walk(payload, encode=False)
        return {
            "context_id": self.context_id,
            "format": kwargs["format"],
            "payload": restored,
            "stats": {"rehydrated": 5, "restricted_credentials": 0, "unknown_aliases": unknown},
        }

    async def delete_context(self, context_id: str) -> None:
        self.calls.append(("delete_context", {"context_id": context_id}))
        self._maybe_fail("delete_context")
        self.deleted = True

    async def aclose(self) -> None:
        self.closed = True

    def _walk(self, value: Any, *, encode: bool) -> Any:
        if isinstance(value, dict):
            return {key: self._walk(child, encode=encode) for key, child in value.items()}
        if isinstance(value, list):
            return [self._walk(child, encode=encode) for child in value]
        if not isinstance(value, str):
            return value
        pairs = self.mapping.items() if encode else ((alias, original) for original, alias in self.mapping.items())
        transformed = value
        for original, replacement in pairs:
            transformed = transformed.replace(original, replacement)
        return transformed
