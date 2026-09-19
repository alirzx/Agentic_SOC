"""Environment helpers for Splunk connector bootstrap."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SplunkBootstrapConfig:
    """Credentials used to register a Splunk connector via the Core API."""

    base_url: str
    token: str
    saved_search: str
    ssl_verify: bool
    poll_interval_seconds: int
    api_base_url: str
    api_token: str
    tenant_id: str
    connector_name: str


def load_bootstrap_config() -> SplunkBootstrapConfig:
    scheme = os.getenv("SPLUNK_SCHEME", "https").strip() or "https"
    host = os.getenv("SPLUNK_HOST", "").strip()
    port = os.getenv("SPLUNK_PORT", "8089").strip() or "8089"
    base_url = os.getenv("SPLUNK_BASE_URL", "").strip()
    if not base_url and host:
        base_url = f"{scheme}://{host}:{port}"
    token = (os.getenv("SPLUNK_TOKEN") or os.getenv("SPLUNK_PASSWORD") or "").strip()
    return SplunkBootstrapConfig(
        base_url=base_url.rstrip("/"),
        token=token,
        saved_search=os.getenv("SPLUNK_SAVED_SEARCH", "AiSOC_Alerts").strip() or "AiSOC_Alerts",
        ssl_verify=_bool_env("SPLUNK_VERIFY_SSL", True),
        poll_interval_seconds=int(os.getenv("SPLUNK_CONNECTOR_POLL_SECONDS", "300") or "300"),
        api_base_url=os.getenv("CORE_API_URL", "http://127.0.0.1:8888").rstrip("/"),
        api_token=os.getenv("AISOC_API_TOKEN", "").strip(),
        tenant_id=os.getenv("AISOC_TENANT_ID", "").strip(),
        connector_name=os.getenv("SPLUNK_CONNECTOR_NAME", "Splunk SIEM").strip() or "Splunk SIEM",
    )
