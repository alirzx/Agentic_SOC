"""Offline smoke test for the tenant-scoped LLM privacy projection."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from app.privacy.context import PRIVACY_TOKEN_KEY_ENV, load_privacy_token_key
from app.privacy.gateway import PrivacyGateway

_EXAMPLE: dict[str, Any] = {
    "src_ip": "10.20.3.7",
    "dest_ip": "10.20.3.21",
    "hostname": "dc01.example.local",
    "user": "EXAMPLE\\analyst",
    "description": "EXAMPLE\\analyst authenticated to dc01.example.local from 10.20.3.7",
    "severity": "high",
    "mitre_techniques": ["T1078"],
    "password": "SyntheticSmokeSecret",
}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Project and locally restore one JSON SOC payload without network calls.")
    parser.add_argument("--input", type=Path, help="JSON input path; omit to use a built-in synthetic example")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--key", help=f"test/dev token key (otherwise {PRIVACY_TOKEN_KEY_ENV}); never printed")
    return parser.parse_args()


def _load(path: Path | None) -> dict[str, Any]:
    if path is None:
        return dict(_EXAMPLE)
    if not path.is_file():
        raise SystemExit(f"Input file not found: {path}. Omit --input to use the built-in synthetic example.")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("Input JSON must be an object.")
    return value


def main() -> int:
    args = _arguments()
    original = _load(args.input)
    key = load_privacy_token_key(args.key or os.getenv(PRIVACY_TOKEN_KEY_ENV))
    gateway = PrivacyGateway(tenant_id=args.tenant_id, token_key=key)
    provider_safe = gateway.project_value(original)
    rehydrated = gateway.process_response(provider_safe)

    original_text = json.dumps(original, sort_keys=True, default=str)
    safe_text = json.dumps(provider_safe, sort_keys=True, default=str)
    for field in ("src_ip", "dest_ip", "hostname", "user"):
        raw = original.get(field)
        if isinstance(raw, str) and raw and raw in safe_text:
            raise SystemExit(f"Invariant failed: {field} survived provider projection")
        if raw is not None and rehydrated.get(field) != raw:
            raise SystemExit(f"Invariant failed: {field} did not rehydrate exactly")
    if original.get("password") and str(original["password"]) in safe_text:
        raise SystemExit("Invariant failed: password survived provider projection")
    if original.get("password") and rehydrated.get("password") != "[REDACTED_SECRET]":
        raise SystemExit("Invariant failed: secret became reversibly restorable")
    if not original_text:
        raise SystemExit("Invariant failed: empty original payload")

    print("ORIGINAL")
    print(json.dumps(original, indent=2, sort_keys=True))
    print("\nPROVIDER_SAFE")
    print(json.dumps(provider_safe, indent=2, sort_keys=True))
    print("\nREHYDRATED")
    print(json.dumps(rehydrated, indent=2, sort_keys=True))
    print("\nINVARIANTS: PASS (offline; zero network calls)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
