#!/usr/bin/env python3
"""Server 55 SOC Investigation acceptance probe (Python stdlib only).

Usage from the HOST checkout, not inside an application container:
    export AISOC_PRIVACY_TEST_TENANT_ID=<existing-DLP-allowlisted-tenant-UUID>
    python3 scripts/soc_investigation_e2e.py
    python3 scripts/soc_investigation_e2e.py --run --alert-id <synthetic-alert-UUID>
    python3 scripts/soc_investigation_e2e.py --resume-run-id <existing-run-id>

Default mode only authenticates, verifies the tenant and lists test-alert IDs.
--run requires a pre-existing test alert and explicit interactive approval.
No credentials, tokens, raw alerts or LLM responses are printed or persisted.
No Docker image, container, repository or runtime configuration is modified.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

BASE = "http://127.0.0.1:8888"  # Server 55 loopback only; no external bearer egress.
HTTP = build_opener(ProxyHandler({}))
_TEST_MARKER = re.compile(r"(?i)(?:^|[^a-z])(?:synthetic|demo|test)(?:$|[^a-z])")
_SAFE_RUN_ID = re.compile(r"[A-Za-z0-9_-]+\Z")


def ask(prompt: str) -> str:
    """Use a read-only TTY; never open a terminal in seek-requiring r+ mode."""
    print(prompt, end="", flush=True)
    try:
        with open("/dev/tty", "r", encoding="utf-8") as tty:
            answer = tty.readline()
    except OSError as exc:
        raise SystemExit("FAIL: An interactive terminal is required") from exc
    if not answer:
        raise SystemExit("FAIL: Interactive terminal closed")
    return answer.strip()


def canonical_uuid(value: str) -> str:
    try:
        normalized = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise SystemExit("FAIL: Invalid UUID") from None
    if normalized != value:
        raise SystemExit("FAIL: UUID must use canonical lowercase form")
    return normalized


def is_test_alert(alert: dict) -> bool:
    """Require an explicit marker, not a substring such as 'latest'."""
    title = str(alert.get("title") or "")
    tags = alert.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    return bool(_TEST_MARKER.search(title)) or any(
        str(tag).lower() in {"synthetic", "demo", "test"} for tag in tags
    )


def api(method: str, path: str, payload: dict | None = None, token: str | None = None) -> dict:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(BASE + path, data=body, headers=headers, method=method)
    safe_path = path.split("?", 1)[0]
    try:
        with HTTP.open(request, timeout=40) as response:
            raw = response.read()
        parsed = json.loads(raw) if raw else {}
        if not isinstance(parsed, dict):
            raise ValueError("Response must be a JSON object")
        return parsed
    except HTTPError as exc:
        code = exc.code
        exc.close()
        hint = {
            401: "Invalid or missing SOC user login/access token",
            403: "User lacks the required permission (often alerts:read)",
            404: "Resource not found for this tenant",
            422: "Request schema validation failed",
            503: "SOC API-to-Agents or tenant-auth dependency unavailable",
        }.get(code, "Check sanitized server-side logs")
        raise SystemExit(f"FAIL: {method} {safe_path} HTTP {code}: {hint}") from None
    except (URLError, TimeoutError) as exc:
        raise SystemExit(f"FAIL: SOC loopback API unreachable ({type(exc).__name__})") from None
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise SystemExit(f"FAIL: {method} {safe_path} returned invalid JSON") from None


def authenticate(expected_tenant: str) -> tuple[str, str]:
    print("=== SOC Authentication ===")
    username = ask("SOC email or username: ")
    if not username:
        raise SystemExit("FAIL: Username cannot be empty")
    try:
        password = getpass.getpass("SOC password: ")
    except (EOFError, OSError) as exc:
        raise SystemExit("FAIL: Interactive password input unavailable") from exc
    try:
        session = api("POST", "/api/v1/auth/login", {"email": username, "password": password})
    finally:
        password = None
    token = session.get("access_token")
    if not isinstance(token, str) or not token:
        raise SystemExit("FAIL: Login did not return an access token")
    print("PASS: Login issued a user JWT (not displayed)")
    me = api("GET", "/api/v1/auth/me", token=token)
    tenant = canonical_uuid(str(me.get("tenant_id", "")))
    if tenant != expected_tenant:
        raise SystemExit("FAIL: SOC user tenant does not match DLP allowlisted tenant")
    print("PASS: /auth/me and authorized tenant match")
    print("ROLE:", str(me.get("role") or "unknown")[:40])
    return token, tenant


def discover_alerts(token: str) -> None:
    print("\n=== Existing test alert IDs (not alert contents) ===")
    found: set[str] = set()
    for keyword in ("synthetic", "demo", "test"):
        query = urlencode({"search": keyword, "page_size": 50})
        page = api("GET", f"/api/v1/alerts?{query}", token=token)
        for alert in page.get("items", []):
            if isinstance(alert, dict) and is_test_alert(alert):
                raw_id = str(alert.get("id", ""))
                try:
                    found.add(canonical_uuid(raw_id))
                except SystemExit:
                    continue
    for alert_id in sorted(found):
        print("TEST_ALERT_ID:", alert_id)
    print("CANDIDATE_COUNT:", len(found))
    print("NOTE: Search covers the newest 50 matches for each test keyword.")


def poll_run(token: str, run_id: str, poll_seconds: int) -> None:
    if not _SAFE_RUN_ID.fullmatch(run_id):
        raise SystemExit("FAIL: Invalid Investigation run ID")
    print("RUN_ID:", run_id)
    deadline = time.monotonic() + poll_seconds
    last_status = None
    while True:
        state = api("GET", f"/api/v1/agents/investigations/{run_id}", token=token)
        status = str(state.get("status") or "unknown")
        if status != last_status:
            print("STATUS:", status, flush=True)
            last_status = status
        if status == "completed":
            print("PASS: Investigation completed")
            print("HAS_FINDINGS:", bool(state.get("findings")))
            print("HAS_RECOMMENDATIONS:", bool(state.get("recommendations")))
            print("ACTION_COUNT:", len(state.get("actions") or []))
            print("MODEL_REPORTED:", bool(state.get("model")))
            return
        if status == "failed":
            raise SystemExit("FAIL: Investigation failed; inspect metadata-only server logs")
        if time.monotonic() >= deadline:
            raise SystemExit(f"PENDING: run_id={run_id}; re-run using --resume-run-id. Do not recreate Agents.")
        time.sleep(5)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true", help="Start Investigation after confirmation on an existing test alert")
    mode.add_argument("--resume-run-id", help="Poll an existing run without starting another Investigation")
    parser.add_argument("--alert-id", help="Existing synthetic/test alert UUID (only with --run)")
    parser.add_argument("--poll-seconds", type=int, default=300, help="Polling limit from 10 to 1800 seconds")
    args = parser.parse_args(argv)
    if not 10 <= args.poll_seconds <= 1800:
        parser.error("--poll-seconds must be between 10 and 1800")
    if args.alert_id and not args.run:
        parser.error("--alert-id requires --run")
    if args.resume_run_id and not _SAFE_RUN_ID.fullmatch(args.resume_run_id):
        parser.error("--resume-run-id contains invalid characters")

    tenant_env = os.environ.get("AISOC_PRIVACY_TEST_TENANT_ID", "")
    if not tenant_env:
        raise SystemExit("FAIL: export AISOC_PRIVACY_TEST_TENANT_ID with the existing authorized UUID")
    tenant = canonical_uuid(tenant_env)
    token, user_tenant = authenticate(tenant)
    if args.resume_run_id:
        poll_run(token, args.resume_run_id, args.poll_seconds)
        return
    if not args.run:
        discover_alerts(token)
        print("PASS: Authentication / authorized tenant / read-only test alert discovery")
        return

    alert_id = canonical_uuid(args.alert_id or ask("Existing synthetic alert UUID: "))
    alert = api("GET", f"/api/v1/alerts/{alert_id}", token=token)
    if str(alert.get("tenant_id")) != user_tenant:
        raise SystemExit("FAIL: Alert is not owned by the authenticated tenant")
    if not is_test_alert(alert):
        raise SystemExit("FAIL: Alert lacks an explicit synthetic/demo/test marker; refusing to run")
    print("PASS: Existing test alert and tenant ownership verified")
    if ask("Type RUN to start Investigation (changes the test alert state): ") != "RUN":
        raise SystemExit("Cancelled; no Investigation started")
    started = api("POST", "/api/v1/agents/investigate", {"alertId": alert_id}, token=token)
    run_id = str(started.get("id") or "")
    if not _SAFE_RUN_ID.fullmatch(run_id):
        raise SystemExit("FAIL: Investigation start returned an invalid run ID")
    print("INITIAL_STATUS:", started.get("status") or "unknown")
    poll_run(token, run_id, args.poll_seconds)


if __name__ == "__main__":
    main()
