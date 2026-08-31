#!/usr/bin/env python3
"""Splunk REST connectivity diagnostic (Phase 8.7).

Tests configuration, authentication, server info, and a safe read-only search.
Never prints secrets.

Usage::

    python scripts/test_splunk_gateway.py

Manual curl equivalent (replace password from env)::

    curl -k -u 'api:<PASSWORD_FROM_ENV>' \\
      "https://192.168.0.107:8089/services/server/info?output_mode=json"

Exit codes:
    0  Connectivity + auth + search OK
    1  Configuration or Splunk failure
    2  Import / dependency error
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_AGENTS_ROOT = _REPO_ROOT / "services" / "agents"
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_AGENTS_ROOT))

from scripts.load_repo_dotenv import load_repo_dotenv


async def _run() -> int:
    from app.integrations.splunk.client import SplunkClient
    from app.integrations.splunk.config import describe_splunk_config, load_splunk_config
    from app.integrations.splunk.spl_policy import ensure_search_prefix
    from app.integrations.splunk.tool import run_splunk_search

    config = load_splunk_config()
    desc = describe_splunk_config(config)
    print("Splunk Gateway Diagnostic")
    print("-------------------------")
    print()
    print(f"Splunk Base URL: {desc.get('base_url')}")
    print(f"Username: {desc.get('username')}")
    print(f"Password: present={desc.get('password_present')}")
    print(f"TLS verification: {desc.get('verify_ssl')}")
    print(f"Enabled: {desc.get('enabled')}")
    print()
    if not config.enabled:
        print("Connectivity: SKIPPED (SPLUNK_ENABLED=false)")
        return 1
    if not config.base_url or not config.username or not config.password:
        missing = []
        if not config.base_url:
            missing.append("base_url")
        if not config.username:
            missing.append("username")
        if not config.password:
            missing.append("password")
        print(f"Connectivity: CONFIGURATION_ERROR (missing: {', '.join(missing)})")
        return 1
    client = SplunkClient(config)
    health = await client.health_check()
    print(f"Connectivity: {'OK' if health.get('status') == 'HEALTHY' else health.get('status')}")
    if health.get("status") != "HEALTHY":
        return 1
    print("Authentication: OK")
    print(f"Server Info: OK (version={health.get('version', 'unknown')})")
    safe_query = ensure_search_prefix("index=* | head 5")
    result = await run_splunk_search(
        safe_query,
        earliest="-60m",
        latest="now",
        max_events=5,
    )
    print(f"Search: {'OK' if result.status.startswith('SUCCESS') or result.status == 'SPLUNK_RESULT_TRUNCATED' else result.status}")
    print(f"SID: {result.search_id}")
    print(f"Events: {result.event_count}")
    print(f"Duration_ms: {result.duration_ms}")
    print(f"Status: {result.status}")
    if result.events:
        ev = result.events[0]
        print(f"Sample evidence_id: {ev.evidence_id}")
        print(f"Sample index: {ev.index} sourcetype: {ev.sourcetype} host: {ev.host}")
    sysmon_query = ensure_search_prefix("index=sysmon EventID=1 | head 10")
    sysmon_result = await run_splunk_search(sysmon_query, earliest="-60m", latest="now", max_events=10)
    print()
    print("Sysmon search:")
    print(f"  status={sysmon_result.status} sid={sysmon_result.search_id} events={sysmon_result.event_count}")
    if sysmon_result.events:
        sample = sysmon_result.events[0]
        print(f"  sample_evidence_id={sample.evidence_id}")
        print(f"  sample_index={sample.index} sourcetype={sample.sourcetype}")
        sysmon = sample.fields.get("sysmon") if sample.fields else None
        if isinstance(sysmon, dict):
            print(f"  sysmon_parse_status={sysmon.get('parse_status')}")
            for key in ("EventID", "Image", "User", "ParentImage"):
                if sysmon.get(key):
                    print(f"  {key}={sysmon.get(key)}")
    if result.status.startswith("SPLUNK_") and result.status not in {
        "SPLUNK_RESULT_TRUNCATED",
    }:
        return 1
    if result.event_count == 0:
        print("Search: NO_EVENTS")
        return 1
    return 0


def main() -> None:
    load_repo_dotenv()
    try:
        code = asyncio.run(_run())
    except ImportError as exc:
        print(f"Import error: {exc}")
        sys.exit(2)
    sys.exit(code)


if __name__ == "__main__":
    main()
