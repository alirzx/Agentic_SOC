"""One-day console session: JWT hard-cap and super-admin role."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.security import (
    ASSIGNABLE_ROLES,
    create_access_token,
    create_refresh_token,
    decode_token,
    has_permission,
    is_privileged_role,
    session_is_expired,
)


def test_super_admin_has_full_permissions() -> None:
    assert has_permission("super_admin", "users:write")
    assert has_permission("super_admin", "roles:write")
    assert has_permission("super_admin", "alerts:delete")
    assert is_privileged_role("super_admin")
    assert "super_admin" in ASSIGNABLE_ROLES


def test_access_token_cannot_extend_past_one_day_from_login() -> None:
    auth_time = int((datetime.now(UTC) - timedelta(hours=23, minutes=30)).timestamp())
    token = create_access_token({"sub": "u1", "role": "admin"}, auth_time=auth_time)
    payload = decode_token(token)
    assert payload["auth_time"] == auth_time
    assert payload["exp"] <= auth_time + 24 * 60 * 60 + 1


def test_session_is_expired_after_one_day() -> None:
    stale = int((datetime.now(UTC) - timedelta(days=2)).timestamp())
    assert session_is_expired({"auth_time": stale}) is True
    fresh = int(datetime.now(UTC).timestamp())
    assert session_is_expired({"auth_time": fresh}) is False
    assert session_is_expired({}) is False


def test_refresh_token_keeps_original_auth_time() -> None:
    auth_time = int(datetime.now(UTC).timestamp())
    token = create_refresh_token({"sub": "u1"}, auth_time=auth_time)
    payload = decode_token(token)
    assert payload["auth_time"] == auth_time
    assert payload["type"] == "refresh"
