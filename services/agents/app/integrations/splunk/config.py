"""Splunk environment configuration (Phase 8.7)."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class SplunkConfig:
    enabled: bool
    base_url: str
    username: str
    password: str
    verify_ssl: bool
    timeout_seconds: float
    max_events_per_query: int
    max_query_window_minutes: int
    max_query_length: int
    poll_interval_seconds: float
    max_poll_seconds: float
    max_tool_calls_per_investigation: int

    @property
    def host(self) -> str:
        return self.base_url.split("//")[-1].split("/")[0].split(":")[0]

    @property
    def port(self) -> int:
        host_part = self.base_url.split("//")[-1].split("/")[0]
        if ":" in host_part:
            return int(host_part.split(":")[1])
        return 8089


def load_splunk_config() -> SplunkConfig:
    scheme = os.getenv("SPLUNK_SCHEME", "https").strip() or "https"
    host = os.getenv("SPLUNK_HOST", "").strip()
    port = os.getenv("SPLUNK_PORT", "8089").strip() or "8089"
    base_url = os.getenv("SPLUNK_BASE_URL", "").strip()
    if not base_url and host:
        base_url = f"{scheme}://{host}:{port}"
    return SplunkConfig(
        enabled=_bool_env("SPLUNK_ENABLED", False),
        base_url=base_url.rstrip("/"),
        username=os.getenv("SPLUNK_USERNAME", "").strip(),
        password=os.getenv("SPLUNK_PASSWORD", "").strip(),
        verify_ssl=_bool_env("SPLUNK_VERIFY_SSL", True),
        timeout_seconds=_float_env("SPLUNK_TIMEOUT_SECONDS", 30.0),
        max_events_per_query=_int_env("SPLUNK_MAX_EVENTS_PER_QUERY", 100),
        max_query_window_minutes=_int_env("SPLUNK_MAX_QUERY_WINDOW_MINUTES", 60),
        max_query_length=_int_env("SPLUNK_MAX_QUERY_LENGTH", 2000),
        poll_interval_seconds=_float_env("SPLUNK_POLL_INTERVAL_SECONDS", 0.5),
        max_poll_seconds=_float_env("SPLUNK_MAX_POLL_SECONDS", 30.0),
        max_tool_calls_per_investigation=_int_env("SPLUNK_MAX_TOOL_CALLS_PER_INVESTIGATION", 5),
    )


def describe_splunk_config(config: SplunkConfig | None = None) -> dict[str, object]:
    cfg = config or load_splunk_config()
    return {
        "enabled": cfg.enabled,
        "base_url": cfg.base_url or "NOT_CONFIGURED",
        "username": cfg.username or "NOT_CONFIGURED",
        "password_present": bool(cfg.password),
        "password_length": len(cfg.password) if cfg.password else 0,
        "verify_ssl": cfg.verify_ssl,
    }
