"""Register a Splunk connector instance against a running AiSOC Core API.

Reads Splunk credentials from the environment (``.env``), then POSTs
``/api/v1/connectors`` so the connectors scheduler picks up the instance.

Prefer the Connectors UI for day-to-day setup; this CLI is for automation.

Usage::

    python scripts/splunk_bootstrap.py
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

from .config import load_bootstrap_config


def _post_json(url: str, body: dict, headers: dict[str, str]) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def main() -> int:
    cfg = load_bootstrap_config()
    if not cfg.base_url:
        print("[splunk] set SPLUNK_BASE_URL (or SPLUNK_HOST)", file=sys.stderr)
        return 2
    if not cfg.token and not (cfg.username and cfg.password):
        print("[splunk] set SPLUNK_TOKEN or SPLUNK_USERNAME + SPLUNK_PASSWORD", file=sys.stderr)
        return 2
    if not cfg.api_token:
        print("[splunk] set AISOC_API_TOKEN (JWT) to create the connector", file=sys.stderr)
        return 2

    headers: dict[str, str] = {"Authorization": f"Bearer {cfg.api_token}"}
    if cfg.tenant_id:
        headers["X-Tenant-ID"] = cfg.tenant_id

    auth_config: dict = {
        "base_url": cfg.base_url,
        "ssl_verify": cfg.ssl_verify,
        "earliest_time": cfg.earliest_time,
    }
    if cfg.token:
        auth_config["token"] = cfg.token
    else:
        auth_config["username"] = cfg.username
        auth_config["password"] = cfg.password
    if cfg.custom_search:
        auth_config["custom_search"] = cfg.custom_search
    if cfg.saved_search:
        auth_config["saved_search"] = cfg.saved_search

    payload = {
        "name": cfg.connector_name,
        "connector_type": "splunk",
        "category": "siem",
        "auth_config": auth_config,
        "connector_config": {
            "poll_interval_seconds": cfg.poll_interval_seconds,
        },
    }

    url = f"{cfg.api_base_url}/api/v1/connectors"
    print(f"[splunk] POST {url} name={cfg.connector_name!r} base_url={cfg.base_url}")
    try:
        result = _post_json(url, payload, headers)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"[splunk] API error {exc.code}: {detail}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover
        print(f"[splunk] failed: {exc}", file=sys.stderr)
        return 1

    connector_id = result.get("id") or result.get("connector_id") or "?"
    print(f"[splunk] connector registered id={connector_id}")
    print("[splunk] scheduler will poll within ~30s; watch the dashboard for live metrics")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
