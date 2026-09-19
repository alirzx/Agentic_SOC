"""One-shot probe: ES correlation-search catalog against live Splunk.

Reads SPLUNK_* from the environment (repo-root .env is not auto-loaded —
export vars or pass them in the shell). Never prints the password.
"""

from __future__ import annotations

import os
import sys
import time

import httpx

SEARCH = (
    "| rest splunk_server=local count=0 /services/saved/searches "
    "| search action.correlationsearch.enabled=1 "
    "| eval notable_name=title "
    "| eval severity=action.notable.param.severity "
    "| eval annotations=action.correlationsearch.annotations "
    '| table notable_name description search annotations severity '
    '| rename notable_name as "Notable Name", '
    'description as "Description", '
    'search as "Notable SPL", '
    'severity as "Severity" '
    '| sort "Notable Name"'
)


def main() -> int:
    base = (os.getenv("SPLUNK_BASE_URL") or "https://192.168.0.10:8089").rstrip("/")
    user = os.getenv("SPLUNK_USERNAME") or "admin"
    password = os.getenv("SPLUNK_PASSWORD") or ""
    if not password:
        print("[probe] set SPLUNK_PASSWORD", file=sys.stderr)
        return 2
    earliest = os.getenv("SPLUNK_EARLIEST_TIME") or "-90d@d"
    verify = (os.getenv("SPLUNK_VERIFY_SSL") or "false").lower() in {"1", "true", "yes"}
    print(f"[probe] {base} user={user} earliest={earliest} verify_ssl={verify}")
    with httpx.Client(verify=verify, auth=(user, password), timeout=120.0) as client:
        create = client.post(
            f"{base}/services/search/jobs",
            data={
                "search": SEARCH,
                "earliest_time": earliest,
                "latest_time": "now",
                "output_mode": "json",
            },
        )
        print(f"[probe] create status={create.status_code}")
        create.raise_for_status()
        sid = create.json()["sid"]
        print(f"[probe] sid={sid}")
        state = "UNKNOWN"
        for i in range(90):
            st = client.get(f"{base}/services/search/jobs/{sid}", params={"output_mode": "json"})
            state = st.json().get("entry", [{}])[0].get("content", {}).get("dispatchState", "")
            if state in ("DONE", "FAILED", "PAUSED"):
                print(f"[probe] state={state} after {i}s")
                break
            time.sleep(1)
        else:
            print("[probe] job timed out", file=sys.stderr)
            return 1
        if state != "DONE":
            return 1
        res = client.get(
            f"{base}/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": 5000},
        )
        rows = res.json().get("results", [])
        print(f"[probe] rows={len(rows)}")
        for row in rows[:8]:
            name = row.get("Notable Name") or row.get("notable_name")
            sev = row.get("Severity") or row.get("severity")
            print(f"  - {name}  severity={sev}")
        if len(rows) > 8:
            print(f"  … +{len(rows) - 8} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
