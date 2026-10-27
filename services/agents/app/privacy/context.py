"""Request-scoped tenant privacy context for the central LLM boundary."""

from __future__ import annotations

import contextlib
import contextvars
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from typing import Any

from app.privacy.gateway import PrivacyGateway
from app.privacy.remote import RemotePrivacyBackend, RemotePrivacyError

PRIVACY_ENABLED_ENV = "AISOC_LLM_PRIVACY_ENABLED"
PRIVACY_TOKEN_KEY_ENV = "AISOC_PRIVACY_TOKEN_KEY"
PRIVACY_BACKEND_ENV = "AISOC_PRIVACY_BACKEND"


class PrivacyConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PrivacySession:
    tenant_id: str
    gateway: Any


_session: contextvars.ContextVar[PrivacySession | None] = contextvars.ContextVar("aisoc_privacy_session", default=None)


def privacy_enabled() -> bool:
    return os.getenv(PRIVACY_ENABLED_ENV, "0").strip().lower() in {"1", "true", "yes", "on"}


def privacy_backend_name() -> str:
    """Selected backend; local remains the explicit compatibility default."""
    name = os.getenv(PRIVACY_BACKEND_ENV, "local").strip().lower()
    if name not in {"local", "remote"}:
        raise PrivacyConfigurationError(f"{PRIVACY_BACKEND_ENV} must be 'local' or 'remote'")
    return name


def validate_privacy_configuration() -> None:
    """Fail startup for an enabled but incomplete privacy configuration."""
    if not privacy_enabled():
        return
    if privacy_backend_name() == "local":
        load_privacy_token_key()
        return
    try:
        RemotePrivacyBackend.from_environment("00000000-0000-0000-0000-000000000000")
    except RemotePrivacyError as exc:
        raise PrivacyConfigurationError(str(exc)) from exc


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
    if privacy_backend_name() == "remote":
        raise PrivacyConfigurationError("remote privacy requires 'async with async_privacy_context(...)'")
    tenant = str(tenant_id).strip()
    if not tenant:
        raise PrivacyConfigurationError("tenant_id is required when LLM privacy is enabled")
    try:
        tenant = str(uuid.UUID(tenant))
    except (ValueError, TypeError) as exc:
        raise PrivacyConfigurationError(
            "privacy_context requires a canonical tenant UUID; resolve slug/name/default at the async boundary"
        ) from exc
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


@contextlib.asynccontextmanager
async def async_privacy_context(
    tenant_id: str,
    *,
    token_key: str | bytes | None = None,
    remote_backend: RemotePrivacyBackend | None = None,
) -> AsyncIterator[PrivacySession | None]:
    """Bind one tenant-scoped backend for a complete asynchronous workflow."""
    if not privacy_enabled():
        yield None
        return
    tenant = _canonical_tenant(tenant_id)
    current = _session.get()
    if current is not None:
        if current.tenant_id != tenant:
            raise PrivacyConfigurationError("nested privacy context tenant mismatch")
        yield current
        return

    backend_name = privacy_backend_name()
    if backend_name == "local":
        gateway: Any = PrivacyGateway(tenant_id=tenant, token_key=load_privacy_token_key(token_key))
    else:
        if token_key is not None:
            raise PrivacyConfigurationError("token_key is only valid for the local privacy backend")
        gateway = remote_backend or RemotePrivacyBackend.from_environment(tenant)
        if gateway.tenant_id != tenant:
            raise PrivacyConfigurationError("remote privacy backend tenant mismatch")
        try:
            await gateway.start()
        except RemotePrivacyError as exc:
            await gateway.aclose()
            raise PrivacyConfigurationError(str(exc)) from exc

    session = PrivacySession(tenant_id=tenant, gateway=gateway)
    reset = _session.set(session)
    try:
        yield session
    finally:
        _session.reset(reset)
        if backend_name == "remote":
            await gateway.aclose()


def _canonical_tenant(tenant_id: str) -> str:
    tenant = str(tenant_id).strip()
    if not tenant:
        raise PrivacyConfigurationError("tenant_id is required when LLM privacy is enabled")
    try:
        return str(uuid.UUID(tenant))
    except (ValueError, TypeError) as exc:
        raise PrivacyConfigurationError(
            "privacy context requires a canonical tenant UUID; resolve slug/name/default at the async boundary"
        ) from exc


def current_privacy_gateway() -> Any | None:
    if not privacy_enabled():
        return None
    session = _session.get()
    if session is None:
        if privacy_backend_name() == "local":
            load_privacy_token_key()
        else:
            validate_privacy_configuration()
        raise PrivacyConfigurationError("LLM privacy is enabled but no tenant privacy context is bound")
    return session.gateway
