#!/usr/bin/env python3
"""Export one case's alerts as ``llm_payload_only.jsonl`` for TKG ingestion.

Why a standalone script: the API's evaluation path is read-only toward the TKG
by design. Getting new evidence *into* the graph is an operator action with its
own sender (``Soorin_Bidirectional_Temporal_Knowledge_Graph/scripts/agentic_soc``),
so the two directions stay separable and neither can happen by accident.

Usage
-----
    export AISOC_API=http://localhost:8000
    export AISOC_TOKEN=...            # or pass --token
    python scripts/agentic_soc_sync_payload.py --case-id <uuid> --out case.jsonl

Each line is one alert:
    {"alert_id": "...", "tenant_id": "...", "splunk": {...llm_payload...},
     "identity": {"hosts": [...], "users": [...], "ips": [...], ...},
     "title": "...", "severity": "...", "event_time": "..."}
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

#: Kept in sync with ``app/services/tkg_evaluation/bundle.py``. Duplicated on
#: purpose: this script must run without importing the API package.
FIELD_ALIASES = {
    "hosts": ("host", "src_host", "dest_host", "ComputerName", "hostname"),
    "users": ("user", "src_user", "dest_user", "user_name", "Account_Name"),
    "ips": ("src_ip", "dest_ip", "ip", "src", "dest"),
    "domains": ("dest_nt_domain", "domain", "query", "dns_query"),
    "urls": ("url", "uri", "http_url"),
    "hashes": ("file_hash", "md5", "sha1", "sha256", "process_hash"),
    "processes": ("process_name", "process", "Image", "parent_process"),
    "commands": ("command_line", "CommandLine"),
    "techniques": ("mitre_technique_id", "technique_id", "TechniqueId"),
}

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TOKENISH = re.compile(r"^[A-Za-z0-9@._:/\\-]{2,200}$")
SECRET_HINTS = ("password", "passwd", "secret", "token", "api_key", "apikey", "credential")


def _flatten(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            out.extend(_flatten(item))
        return out
    text = str(value).strip()
    return [text] if text and TOKENISH.match(text) else []


def extract_identity(payload: dict) -> dict[str, list[str]]:
    """Pull the correlation keys the TKG's curated profile expects."""

    if not isinstance(payload, dict):
        return {}
    raw = payload.get("payload") if isinstance(payload.get("payload"), dict) else payload
    lowered = {str(key).lower(): value for key, value in raw.items()}
    out: dict[str, list[str]] = {}
    for target, aliases in FIELD_ALIASES.items():
        values: list[str] = []
        for alias in aliases:
            if alias.lower() in lowered:
                values.extend(_flatten(lowered[alias.lower()]))
        if target == "ips" and values:
            values.extend(IPV4.findall(" ".join(values)))
        if values:
            seen: dict[str, None] = {}
            for value in values:
                seen.setdefault(value, None)
            out[target] = list(seen)[:24]
    return out


def scrub(payload):
    """Drop credential-looking keys before a payload leaves the API."""

    if isinstance(payload, dict):
        return {
            key: scrub(value)
            for key, value in payload.items()
            if not any(hint in str(key).lower() for hint in SECRET_HINTS)
        }
    if isinstance(payload, list):
        return [scrub(item) for item in payload]
    return payload


def fetch_case_alerts(api: str, case_id: str, token: str, limit: int) -> list[dict]:
    url = f"{api.rstrip('/')}/api/v1/cases/{case_id}/alerts?limit={limit}"
    request = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    })
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"GET {url} -> HTTP {exc.code}: {exc.read(300)!r}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"GET {url} failed: {exc}") from exc
    if isinstance(data, list):
        return data
    for key in ("alerts", "items", "data"):
        if isinstance(data.get(key), list):
            return data[key]
    raise SystemExit(f"unexpected response shape from {url}: {sorted(data)[:6]}")


def to_record(alert: dict, tenant_id: str | None) -> dict:
    payload = alert.get("llm_payload") or {}
    return {
        "alert_id": str(alert.get("id") or alert.get("alert_id")),
        "tenant_id": tenant_id or alert.get("tenant_id"),
        "title": alert.get("title"),
        "severity": alert.get("severity"),
        "event_time": alert.get("event_time") or alert.get("created_at"),
        "identity": extract_identity(payload),
        "splunk": scrub(payload),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--api", default=os.environ.get("AISOC_API", "http://localhost:8000"))
    parser.add_argument("--token", default=os.environ.get("AISOC_TOKEN", ""))
    parser.add_argument("--tenant-id", default=os.environ.get("AISOC_TENANT_ID", ""))
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--out", default="llm_payload_only.jsonl")
    args = parser.parse_args(argv)

    if not args.token:
        raise SystemExit("Provide --token or set AISOC_TOKEN (the API needs an authenticated session).")

    alerts = fetch_case_alerts(args.api, args.case_id, args.token, args.limit)
    written = 0
    with open(args.out, "w", encoding="utf-8") as handle:
        for alert in alerts:
            record = to_record(alert, args.tenant_id or None)
            if not record["alert_id"]:
                continue
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            written += 1
    print(f"wrote {written} alert(s) to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
