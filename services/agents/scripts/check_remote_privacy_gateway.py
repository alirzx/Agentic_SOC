#!/usr/bin/env python3
"""Non-provider connectivity check for a remote Privacy Gateway.

Only the synthetic payload below is sent. Credentials, context identifiers,
and response bodies are never printed.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from typing import Any

import httpx

SYNTHETIC = {
    "src_ip": "10.20.3.7",
    "hostname": "dc01.corp.example",
    "username": "CORP\\alice",
    "severity": "high",
    "mitre_technique": "T1110.003",
}


def _available_policy_names(payload: dict[str, Any]) -> set[str]:
    """Validate the Gateway policy-list shape and return its profile names."""
    policies = payload.get("policies")
    if not isinstance(policies, list):
        raise RuntimeError("policy response omitted the policies list")
    names: set[str] = set()
    for policy in policies:
        if not isinstance(policy, dict):
            raise RuntimeError("policy response contained a non-object entry")
        name, version = policy.get("name"), policy.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise RuntimeError("policy response contained an invalid entry")
        names.add(name)
    return names


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def _pass(endpoint: str, started: float, *, stats: dict[str, Any] | None = None) -> None:
    fields = ""
    if stats:
        safe_stats = ", ".join(f"{key}={int(value)}" for key, value in sorted(stats.items()) if isinstance(value, int))
        fields = f" ({safe_stats})" if safe_stats else ""
    print(f"PASS {endpoint} {((time.monotonic() - started) * 1000):.1f}ms{fields}")


async def _json(client: httpx.AsyncClient, method: str, path: str, **kwargs: Any) -> tuple[dict[str, Any], float]:
    started = time.monotonic()
    response = await client.request(method, path, **kwargs)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"{path} returned a non-object response")
    return payload, started


async def run() -> int:
    base_url = _required("AISOC_PRIVACY_REMOTE_URL").rstrip("/")
    api_key = _required("AISOC_PRIVACY_REMOTE_API_KEY")
    tenant = _required("AISOC_PRIVACY_TEST_TENANT_ID")
    profile = os.getenv("AISOC_PRIVACY_REMOTE_PROFILE", "agentic-soc-v1").strip()
    timeout = float(os.getenv("AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS", "30"))
    uuid.UUID(tenant)
    if "@" in base_url.split("://", 1)[-1].split("/", 1)[0]:
        raise RuntimeError("Gateway URL must not embed credentials")

    context_id: str | None = None
    headers = {"Authorization": f"Bearer {api_key}"}
    async with httpx.AsyncClient(base_url=base_url, headers=headers, timeout=timeout, follow_redirects=False) as client:
        try:
            health, started = await _json(client, "GET", "/health")
            if health.get("status") != "ok" or health.get("service") != "soorin-data-privacy-gateway":
                raise RuntimeError("unexpected health response")
            _pass("GET /health", started)

            ready, started = await _json(client, "GET", "/ready")
            if ready.get("status") != "ready" or not ready.get("store"):
                raise RuntimeError("Gateway storage is not ready")
            _pass("GET /ready", started)

            policies, started = await _json(client, "GET", "/v1/policies")
            if profile not in _available_policy_names(policies):
                raise RuntimeError("configured profile is not available")
            _pass("GET /v1/policies", started)

            context, started = await _json(
                client,
                "POST",
                "/v1/contexts",
                json={"tenant_id": tenant, "profile": profile, "ttl_seconds": 300},
            )
            context_id = context.get("context_id")
            if (
                not isinstance(context_id, str)
                or not context_id.startswith("ctx_")
                or context.get("tenant_id") != tenant
                or context.get("profile") != profile
                or not isinstance(context.get("policy_version"), str)
                or not isinstance(context.get("expires_at"), str)
            ):
                raise RuntimeError("created context binding does not match request")
            _pass("POST /v1/contexts", started)

            info, started = await _json(client, "GET", f"/v1/contexts/{context_id}")
            if info.get("tenant_id") != tenant or info.get("profile") != profile:
                raise RuntimeError("context inspection binding mismatch")
            _pass("GET /v1/contexts/{id}", started)

            classified, started = await _json(
                client,
                "POST",
                "/v1/classify",
                json={"profile": profile, "format": "json", "payload": SYNTHETIC, "registrations": []},
            )
            if not isinstance(classified.get("counts"), dict) or not isinstance(classified.get("total_detected"), int):
                raise RuntimeError("classify response omitted detection statistics")
            _pass("POST /v1/classify", started, stats={"total_detected": classified["total_detected"]})

            encoded, started = await _json(
                client,
                "POST",
                "/v1/encode",
                json={
                    "context_id": context_id,
                    "tenant_id": tenant,
                    "profile": profile,
                    "purpose": "llm-egress",
                    "format": "json",
                    "payload": SYNTHETIC,
                    "registrations": [
                        {"kind": "HOST", "value": SYNTHETIC["hostname"], "source": "soc.smoke", "role": "host"},
                        {"kind": "USER", "value": SYNTHETIC["username"], "source": "soc.smoke", "role": "user"},
                    ],
                },
            )
            protected = encoded.get("payload")
            if not isinstance(protected, dict) or protected == SYNTHETIC:
                raise RuntimeError("encode did not transform the synthetic identities")
            if any(value in str(protected) for value in (SYNTHETIC["src_ip"], SYNTHETIC["hostname"], SYNTHETIC["username"])):
                raise RuntimeError("encode response retained a synthetic protected identity")
            _pass("POST /v1/encode", started, stats=encoded.get("stats"))

            decoded, started = await _json(
                client,
                "POST",
                "/v1/decode",
                json={
                    "context_id": context_id,
                    "format": "json",
                    "payload": protected,
                    "purpose": "llm-response",
                    "reveal_credentials": False,
                },
            )
            if decoded.get("payload") != SYNTHETIC:
                raise RuntimeError("decode did not exactly restore the synthetic payload")
            if decoded.get("stats", {}).get("unknown_aliases", 0):
                raise RuntimeError("decode reported unknown aliases")
            _pass("POST /v1/decode", started, stats=decoded.get("stats"))
        finally:
            if context_id is not None:
                started = time.monotonic()
                response = await client.delete(f"/v1/contexts/{context_id}")
                response.raise_for_status()
                _pass("DELETE /v1/contexts/{id}", started)
    return 0


def main() -> int:
    try:
        return asyncio.run(run())
    except Exception as exc:  # noqa: BLE001 - CLI prints only a safe category
        status = getattr(getattr(exc, "response", None), "status_code", None)
        suffix = f" HTTP {status}" if isinstance(status, int) else ""
        print(f"FAIL remote privacy connectivity: {type(exc).__name__}{suffix}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
