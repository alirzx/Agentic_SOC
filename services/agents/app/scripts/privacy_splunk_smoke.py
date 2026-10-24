"""Offline privacy smoke test using synthesized Splunk/OCSF alert shapes."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from app.privacy.context import PRIVACY_TOKEN_KEY_ENV, load_privacy_token_key
from app.privacy.gateway import PrivacyGateway

_SAMPLES: dict[str, dict[str, Any]] = {
    "password_spray": {
        "src": "B_309",
        "host": "collector-01.synthetic.test",
        "src_endpoint": {"ip": "B_309"},
        "message": "Synthetic password spray analytic",
        "severity": "medium",
        "class_uid": 2001,
        "category_uid": 2,
        "activity_id": 1,
        "splunk_notable": {
            "src": "B_309",
            "orig_rule_title": "The source [B_309] attempted to access many distinct users.",
            "annotations_mitre_attack": "T1110.003",
        },
        "src_ip": "B_309",
        "event_id": "evt-synthetic-001",
    },
    "registry_host": {
        "dest": "endpoint01.corp.synthetic.test",
        "hostname": "endpoint01.corp.synthetic.test",
        "device": {"name": "endpoint01.corp.synthetic.test"},
        "user": "soc_analyst",
        "splunk_notable": {
            "entity_type": "system",
            "entity": "endpoint01.corp.synthetic.test",
            "risk_object": "endpoint01.corp.synthetic.test",
            "normalized_risk_object": "endpoint01.corp.synthetic.test",
            "orig_rule_title": "Registry modification on endpoint01.corp.synthetic.test",
            "contributing_events_search": (
                "| savedsearch \"Synthetic Registry Rule\" "
                "| search dest=\"endpoint01.corp.synthetic.test\" user=\"soc_analyst\""
            ),
        },
        "session_token": "synthetic-secret-never-send",
        "connector_id": "connector-synthetic-002",
    },
    "firewall_placeholder": {
        "dest": "noc-pc.corp.synthetic.test",
        "device": {"name": "noc-pc.corp.synthetic.test"},
        "user": "unknown",
        "splunk_notable": {
            "entity_type": "user",
            "entity": "unknown",
            "risk_object": "unknown",
            "normalized_risk_object": "unknown",
            "orig_rule_title": (
                "Suspicious firewall modification on endpoint "
                "noc-pc.corp.synthetic.test by user unknown."
            ),
            "contributing_events_search": "| search user=\"unknown\"",
        },
        "finding": {"uid": "finding-synthetic-003"},
    },
}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Project and restore synthetic Splunk schemas without making network calls."
    )
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--key", help=f"test/dev token key (otherwise {PRIVACY_TOKEN_KEY_ENV}); never printed")
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    key = load_privacy_token_key(args.key or os.getenv(PRIVACY_TOKEN_KEY_ENV))
    gateway = PrivacyGateway(tenant_id=args.tenant_id, token_key=key)
    provider_safe = gateway.project_value(_SAMPLES)
    rehydrated = gateway.process_response(provider_safe)
    safe_text = json.dumps(provider_safe, sort_keys=True)

    for private in (
        "B_309",
        "endpoint01.corp.synthetic.test",
        "noc-pc.corp.synthetic.test",
        "soc_analyst",
        "synthetic-secret-never-send",
    ):
        if private in safe_text:
            raise SystemExit(f"Invariant failed: private synthetic value survived projection: {private}")
    if "IP_OPAQUE_" not in safe_text:
        raise SystemExit("Invariant failed: opaque IP alias missing")
    if "T1110.003" not in safe_text:
        raise SystemExit("Invariant failed: public security metadata was removed")
    if provider_safe["firewall_placeholder"]["user"] != "unknown":
        raise SystemExit("Invariant failed: placeholder semantics were lost")
    if "USER_" in json.dumps(provider_safe["firewall_placeholder"], sort_keys=True):
        raise SystemExit("Invariant failed: placeholder created a user alias")
    if provider_safe["registry_host"]["session_token"] != "[REDACTED_SECRET]":
        raise SystemExit("Invariant failed: secret was not irreversibly masked")
    if rehydrated["password_spray"]["src_ip"] != "B_309":
        raise SystemExit("Invariant failed: opaque IP did not rehydrate")
    if rehydrated["registry_host"]["dest"] != _SAMPLES["registry_host"]["dest"]:
        raise SystemExit("Invariant failed: host did not rehydrate")
    if rehydrated["registry_host"]["session_token"] != "[REDACTED_SECRET]":
        raise SystemExit("Invariant failed: secret became reversible")
    if provider_safe["registry_host"]["connector_id"] != "connector-synthetic-002":
        raise SystemExit("Invariant failed: non-private connector ID changed")

    print("ORIGINAL")
    print(json.dumps(_SAMPLES, indent=2, sort_keys=True))
    print("\nPROVIDER_SAFE")
    print(json.dumps(provider_safe, indent=2, sort_keys=True))
    print("\nREHYDRATED")
    print(json.dumps(rehydrated, indent=2, sort_keys=True))
    print("\nINVARIANTS: PASS (offline; zero network calls)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
