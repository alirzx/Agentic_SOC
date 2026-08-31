#!/usr/bin/env python3
"""LLM gateway connectivity diagnostic (Phase 8.6.1).

Minimal authenticated completion through the existing ``app.llm.factory`` path.
Never prints secrets.

Usage::

    python scripts/test_llm_gateway.py

Exit codes:
    0  Authentication + completion OK
    1  Configuration or provider failure
    2  Import / dependency error
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_AGENTS_ROOT = _REPO_ROOT / "services" / "agents"
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_AGENTS_ROOT))

from scripts.load_repo_dotenv import load_repo_dotenv


def _print_header() -> None:
    print("LLM Gateway Diagnostic")
    print("----------------------")
    print()


def _print_config(config: dict) -> None:
    api = config.get("api_key") or {}
    print(f"Base URL: {config.get('base_url_normalized_sanitized', 'NOT_CONFIGURED')}")
    if config.get("base_url_issues"):
        for issue in config["base_url_issues"]:
            print(f"  warning: {issue}")
    if config.get("embedded_path_token_detected") and not config.get("api_key_matches_embedded_path_token"):
        print("  note: gateway token is embedded in BASE_URL path; OPENAI_API_KEY is a separate credential")
    print(f"Model: {config.get('model_triage', 'UNKNOWN')}")
    print("API Key:")
    print(f"  present={api.get('present', False)}")
    if api.get("present"):
        print(f"  length={api.get('length', 0)}")
        print(f"  prefix={api.get('prefix', '')}")
    print()


async def _run_completion(model_role: str = "triage") -> dict:
    from langchain_core.messages import HumanMessage

    from app.core.cost_telemetry import CostTracker
    from app.llm import safe_ainvoke
    from app.llm.factory import make_chat_model, resolve_model_alias
    from app.llm.provider_errors import classify_llm_exception, failure_causes, sanitize_error_message

    model = resolve_model_alias(model_role)
    llm = make_chat_model(model_role, temperature=0.0, max_tokens=16)
    started = time.monotonic()
    async with CostTracker(run_id="llm-gateway-diag", tenant_id="diag") as tracker:
        try:
            result = await safe_ainvoke(llm, [HumanMessage(content="Return exactly: OK")])
            latency_ms = (time.monotonic() - started) * 1000.0
            content = str(getattr(result, "content", "") or "").strip()
            summary = tracker.summary()
            rec = tracker._records[-1] if tracker._records else None
            return {
                "ok": True,
                "http_status": 200,
                "latency_ms": latency_ms,
                "model": model,
                "completion": content[:80],
                "provider": os.getenv("OPENAI_BASE_URL", "").split("//")[1].split("/")[0] if "//" in os.getenv("OPENAI_BASE_URL", "") else "UNKNOWN",
                "input_tokens": rec.prompt_tokens if rec else 0,
                "output_tokens": rec.completion_tokens if rec else 0,
                "total_tokens": summary.get("total_tokens", 0),
                "estimated_cost": tracker.total_cost_usd,
                "cost_status": "MEASURED" if (rec and (rec.prompt_tokens or rec.completion_tokens)) else "ESTIMATED",
                "call_count": summary.get("call_count", 0),
            }
        except Exception as exc:  # noqa: BLE001
            classified = classify_llm_exception(exc)
            latency_ms = (time.monotonic() - started) * 1000.0
            status = classified.http_status or 0
            return {
                "ok": False,
                "http_status": status,
                "latency_ms": latency_ms,
                "model": model,
                "category": classified.category,
                "error": sanitize_error_message(str(exc)),
                "possible_causes": failure_causes(classified.category),
            }


def _print_success(result: dict) -> None:
    print(f"HTTP Status: {result.get('http_status', 200)}")
    print(f"Latency: {int(result.get('latency_ms', 0))} ms")
    print()
    print("Authentication: OK")
    print("Model: OK")
    print(f"Completion: OK ({result.get('completion', '')})")
    print()
    print(f"Provider: {result.get('provider', 'UNKNOWN')}")
    print(f"Input tokens: {result.get('input_tokens', 0)}")
    print(f"Output tokens: {result.get('output_tokens', 0)}")
    print(f"Total tokens: {result.get('total_tokens', 0)}")
    print(f"Cost status: {result.get('cost_status', 'NOT_AVAILABLE')}")
    if result.get("cost_status") == "ESTIMATED":
        print("Estimated cost: provider did not return token usage")
    else:
        print(f"Estimated cost: ${result.get('estimated_cost', 0.0):.6f}")
    print(f"LLM calls: {result.get('call_count', 0)}")


def _print_failure(config: dict, result: dict | None) -> None:
    if not config.get("llm_configured"):
        print("HTTP Status: —")
        print("Authentication: FAILED")
        print()
        print("Possible causes:")
        print("- missing OPENAI_BASE_URL")
        print("- missing OPENAI_API_KEY")
        return
    if result is None:
        return
    status = result.get("http_status") or "—"
    print(f"HTTP Status: {status}")
    print("Authentication: FAILED")
    print()
    print(f"Category: {result.get('category', 'UNKNOWN')}")
    if result.get("error"):
        print(f"Error: {result.get('error')}")
    print()
    print("Possible causes:")
    for cause in result.get("possible_causes") or []:
        print(f"- {cause}")


async def main_async() -> int:
    load_repo_dotenv()
    try:
        from app.llm.gateway_config import validate_gateway_config
    except ImportError as exc:
        print(f"Import error: {exc}")
        return 2
    _print_header()
    config = validate_gateway_config()
    _print_config(config)
    if not config.get("llm_configured"):
        _print_failure(config, None)
        return 1
    result = await _run_completion()
    if result.get("ok"):
        _print_success(result)
        return 0
    _print_failure(config, result)
    return 1


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
