"""Request-scoped tenant privacy context for the central LLM boundary."""

from __future__ import annotations

import contextlib
import contextvars
import os
from collections.abc import Iterator
from dataclasses import dataclass

from app.privacy.gateway import PrivacyGateway

PRIVACY_ENABLED_ENV = "AISOC_LLM_PRIVACY_ENABLED"
PRIVACY_TOKEN_KEY_ENV = "AISOC_PRIVACY_TOKEN_KEY"


class PrivacyConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PrivacySession:
    tenant_id: str
    gateway: PrivacyGateway


_session: contextvars.ContextVar[PrivacySession | None] = contextvars.ContextVar("aisoc_privacy_session", default=None)


def privacy_enabled() -> bool:
    return os.getenv(PRIVACY_ENABLED_ENV, "0").strip().lower() in {"1", "true", "yes", "on"}


def load_privacy_token_key(explicit: str | bytes | None = None) -> bytes:
    raw = explicit if explicit is not None else os.getenv(PRIVACY_TOKEN_KEY_ENV, "")
    key = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw or b"")
    if len(key) < 32:
        raise PrivacyConfigurationError(f"{PRIVACY_TOKEN_KEY_ENV} must contain at least 32 bytes when privacy is enabled")
    return key


@contextlib.contextmanager
def privacy_context(tenant_id: str, *, token_key: str | bytes | None = None) -> Iterator[PrivacySession | None]:
    if not privacy_enabled():
        yield None
        return
    tenant = str(tenant_id).strip()
    if not tenant:
        raise PrivacyConfigurationError("tenant_id is required when LLM privacy is enabled")
    current = _session.get()
    if current is not None and current.tenant_id == tenant and token_key is None:
        yield current
        return
    session = PrivacySession(tenant_id=tenant, gateway=PrivacyGateway(tenant_id=tenant, token_key=load_privacy_token_key(token_key)))
    reset = _session.set(session)
    try:
        yield session
    finally:
        _session.reset(reset)


def current_privacy_gateway() -> PrivacyGateway | None:
    if not privacy_enabled():
        return None
    session = _session.get()
    if session is None:
        load_privacy_token_key()
        raise PrivacyConfigurationError("LLM privacy is enabled but no tenant privacy context is bound")
    return session.gateway
