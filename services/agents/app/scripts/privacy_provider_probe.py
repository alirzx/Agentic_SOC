"""Explicit opt-in real-provider probe for the production auto-triage path."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from urllib.parse import urlparse

from app.agents.auto_triage_agent import run_auto_triage
from app.llm.factory import resolve_base_url, resolve_model_alias
from app.privacy.context import PRIVACY_TOKEN_KEY_ENV, load_privacy_token_key, privacy_context
from app.privacy.gateway import PrivacyGateway
from app.workers.fused_alert_consumer import build_state

_TENANT = "00000000-0000-0000-0000-000000000071"
_FUSED_MESSAGE = {
    "id": "00000000-0000-0000-0000-000000000072",
    "tenant_id": _TENANT,
    "confidence_score": 0.84,
    "fusion_decision": "promote",
    "narrative": "Synthetic password spray followed by a successful authentication.",
    "alert": {
        "id": "00000000-0000-0000-0000-000000000072",
        "title": "Synthetic password spray against a tenant account",
        "severity": "high",
        "src_ip": "B_309",
        "hostname": "endpoint01.corp.synthetic.test",
        "username": "soc_analyst",
        "mitre_techniques": ["T1110.003", "T1078"],
        "risk_score": 82,
        "connector_id": "connector-synthetic-provider-probe",
        "connector_type": "splunk",
        "source_event_ids": ["event-synthetic-provider-probe"],
    },
}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="REAL NETWORK CALL: run synthetic fused-alert auto-triage through the configured provider."
    )
    parser.add_argument("--privacy", choices=("on", "off"), required=True)
    return parser.parse_args()


def _safe_route(url: str | None) -> str:
    if not url:
        return "provider-default"
    parsed = urlparse(url)
    host = parsed.hostname or "configured-host"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    suffix = "/v1" if parsed.path.rstrip("/").endswith("/v1") else "/..."
    return f"{parsed.scheme}://{host}/...{suffix}"


async def _run(privacy_mode: str) -> int:
    os.environ["AISOC_LLM_PRIVACY_ENABLED"] = "1" if privacy_mode == "on" else "0"
    if not os.getenv("OPENAI_API_KEY", "").strip():
        raise SystemExit("OPENAI_API_KEY is required. The value is never printed.")

    state = build_state(_FUSED_MESSAGE)
    if state is None:
        raise SystemExit("Synthetic fused message did not build an InvestigationState.")

    print("WARNING: this command performs a real network/provider call.")
    print(f"ROUTE: {_safe_route(resolve_base_url())}")
    print(f"MODEL ROLE: triage ({resolve_model_alias('triage')})")
    print(f"PRIVACY: {privacy_mode.upper()}")

    if privacy_mode == "on":
        key = load_privacy_token_key(os.getenv(PRIVACY_TOKEN_KEY_ENV))
        preview = PrivacyGateway(tenant_id=str(state.tenant_id), token_key=key).project_value(
            {"alert_summary": state.alert_summary, "raw_alert": state.raw_alert}
        )
        print("PROVIDER_SAFE_PREVIEW")
        print(json.dumps(preview, indent=2, sort_keys=True, default=str))

    try:
        with privacy_context(str(state.tenant_id)):
            result = await run_auto_triage(state)
    except Exception as exc:  # noqa: BLE001 - CLI reports a credential-safe category only
        print(f"PROVIDER PROBE: FAIL ({type(exc).__name__})")
        return 1

    print("LOCAL_RESULT")
    print(
        json.dumps(
            {
                "verdict": result.verdict,
                "confidence": result.confidence,
                "status": result.status.value,
            },
            indent=2,
            sort_keys=True,
        )
    )
    print("PROVIDER PROBE: PASS")
    return 0


def main() -> int:
    return asyncio.run(_run(_arguments().privacy))


if __name__ == "__main__":
    raise SystemExit(main())
