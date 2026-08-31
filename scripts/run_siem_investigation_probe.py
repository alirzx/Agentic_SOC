#!/usr/bin/env python3
"""Phase 8.7.3 — Live Splunk + SIEM agent E2E (run on Linux VM with real .env).

Usage::

    python scripts/run_siem_investigation_probe.py --timeout 300

Exit 0 only when live Splunk returns events AND agent splunk_events > 0.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_AGENTS_ROOT = _REPO_ROOT / "services" / "agents"
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_AGENTS_ROOT))

from scripts.load_repo_dotenv import load_repo_dotenv


async def _splunk_live_probe() -> dict[str, object]:
    from app.integrations.splunk.client import SplunkClient
    from app.integrations.splunk.config import describe_splunk_config, load_splunk_config
    from app.integrations.splunk.spl_policy import ensure_search_prefix
    from app.integrations.splunk.tool import run_splunk_search

    started = time.monotonic()
    config = load_splunk_config()
    desc = describe_splunk_config(config)
    out: dict[str, object] = {"config": desc, "splunk_duration_ms": 0}
    if not config.enabled or not config.password or not config.username:
        out["status"] = "CONFIGURATION_ERROR"
        return out
    client = SplunkClient(config)
    health_started = time.monotonic()
    health = await client.health_check()
    out["health_latency_ms"] = int((time.monotonic() - health_started) * 1000)
    out["health"] = health
    if health.get("status") != "HEALTHY":
        out["status"] = health.get("status")
        out["splunk_duration_ms"] = int((time.monotonic() - started) * 1000)
        return out
    search_started = time.monotonic()
    search_query = ensure_search_prefix("index=* | head 5")
    result = await run_splunk_search(search_query, earliest="-60m", latest="now", max_events=5)
    out["search_duration_ms"] = int((time.monotonic() - search_started) * 1000)
    out["search_status"] = result.status
    out["sid"] = result.search_id
    out["event_count"] = result.event_count
    out["duration_ms"] = result.duration_ms
    out["truncated"] = result.truncated
    out["query_hash"] = result.query_hash
    if result.events:
        sample = result.events[0]
        out["sample_evidence_id"] = sample.evidence_id
        out["sample_event_time"] = sample.event_time
        out["sample_fields"] = sorted(sample.fields.keys())[:30]
        out["sample_top_level"] = {
            k: v
            for k, v in {
                "_time": sample.event_time,
                "host": sample.host,
                "index": sample.index,
                "sourcetype": sample.sourcetype,
                "src_ip": sample.src_ip,
                "dest_ip": sample.dest_ip,
                "user": sample.user,
            }.items()
            if v
        }
    no_started = time.monotonic()
    no_result = await run_splunk_search(
        ensure_search_prefix("index=* aisoc_probe_no_match_xyz=impossible_value_12345"),
        earliest="-5m",
        max_events=5,
    )
    out["no_results_duration_ms"] = int((time.monotonic() - no_started) * 1000)
    out["no_results_status"] = no_result.status
    out["splunk_duration_ms"] = int((time.monotonic() - started) * 1000)
    out["status"] = "OK" if result.event_count > 0 else "NO_EVENTS"
    return out


def _extract_evidence_report(metrics: dict[str, object]) -> dict[str, object]:
    inv = metrics.get("investigation_state") or {}
    if not isinstance(inv, dict):
        return {"evidence_ids": [], "claims": []}
    evidence_ids = list(inv.get("evidence_ids") or [])
    claims = []
    for raw in inv.get("claims") or []:
        if isinstance(raw, dict):
            claims.append(
                {
                    "claim": raw.get("claim"),
                    "evidence_ids": raw.get("evidence_ids") or [],
                    "status": raw.get("status"),
                    "confidence": raw.get("confidence"),
                }
            )
    splunk_ids = [eid for eid in evidence_ids if str(eid).startswith("splunk:")]
    splunk_claims = [c for c in claims if any(str(eid).startswith("splunk:") for eid in c.get("evidence_ids", []))]
    grounded = [c for c in splunk_claims if c.get("status") == "supported"]
    unsupported = [c for c in claims if c.get("status") == "unsupported"]
    return {
        "evidence_ids": evidence_ids,
        "splunk_evidence_ids": splunk_ids,
        "claims": claims,
        "splunk_claims": splunk_claims,
        "grounded_splunk_claims": grounded,
        "unsupported_claims": unsupported,
        "investigation_status": inv.get("status") or inv.get("execution_mode"),
    }


async def _run_agent_probe(timeout: float) -> dict[str, object]:
    from app.runtime.evaluation.service import AgenticEvaluationService

    started = time.monotonic()
    svc = AgenticEvaluationService(timeout=timeout)
    run = await svc.run_evaluation("golden-siem", limit=1, write_reports=False)
    row = svc.get_cases(run.id)[0] if svc.get_cases(run.id) else None
    metrics = dict(row.metric_details) if row else {}
    inv_exec = metrics.get("investigation_execution") or {}
    tool_calls = row.tool_calls if row else []
    splunk_calls = [t for t in tool_calls if t.get("tool_name") == "splunk_search"]
    evidence_report = _extract_evidence_report(metrics)
    splunk_meta = metrics.get("splunk_tool_metadata") or []
    splunk_search_ms = sum(int(m.get("duration_ms") or 0) for m in splunk_meta if isinstance(m, dict))
    return {
        "run_id": run.id,
        "investigation_duration_ms": int((time.monotonic() - started) * 1000),
        "execution_mode": metrics.get("execution_mode"),
        "llm_calls": metrics.get("llm_calls", 0),
        "splunk_tool_calls": metrics.get("splunk_tool_calls", 0),
        "splunk_events": metrics.get("splunk_events", 0),
        "splunk_status": metrics.get("splunk_status"),
        "cost_status": run.cost_status,
        "cost": run.estimated_cost,
        "agentic_score": row.overall_score if row else None,
        "investigation_parse_status": inv_exec.get("parse_status"),
        "investigation_completed": inv_exec.get("parse_status") == "VALID",
        "splunk_tool_call_records": splunk_calls,
        "splunk_search_duration_ms": splunk_search_ms,
        **evidence_report,
    }


async def _main(args: argparse.Namespace) -> int:
    load_repo_dotenv()
    total_started = time.monotonic()
    print("SIEM Investigation Probe (Phase 8.7.3)")
    print("----------------------------------------")
    splunk = await _splunk_live_probe()
    print()
    print("Splunk live:")
    cfg = splunk.get("config") or {}
    print(f"  SPLUNK_ENABLED={cfg.get('enabled')}")
    print(f"  base_url={cfg.get('base_url')}")
    print(f"  username={cfg.get('username')}")
    print(f"  password_present={cfg.get('password_present')}")
    print(f"  verify_ssl={cfg.get('verify_ssl')}")
    print(f"  status={splunk.get('status')}")
    if splunk.get("health"):
        print(f"  health={splunk['health']} latency_ms={splunk.get('health_latency_ms')}")
    if splunk.get("search_status"):
        print(
            f"  search_status={splunk.get('search_status')} sid={splunk.get('sid')} "
            f"events={splunk.get('event_count')} duration_ms={splunk.get('duration_ms')} "
            f"truncated={splunk.get('truncated')}"
        )
        if splunk.get("sample_top_level"):
            print(f"  sample_event={splunk.get('sample_top_level')}")
        if splunk.get("sample_fields"):
            print(f"  sample_fields={splunk.get('sample_fields')}")
        print(f"  no_results_status={splunk.get('no_results_status')}")
    print(f"  splunk_probe_duration_ms={splunk.get('splunk_duration_ms')}")
    if args.splunk_only:
        return 0 if splunk.get("status") == "OK" else 1
    print()
    print("Agent probe (GOLDEN-SIEM-AUTH):")
    agent = await _run_agent_probe(args.timeout)
    for key in (
        "execution_mode",
        "llm_calls",
        "splunk_tool_calls",
        "splunk_events",
        "splunk_status",
        "cost_status",
        "cost",
        "agentic_score",
        "investigation_completed",
        "splunk_evidence_ids",
        "grounded_splunk_claims",
        "unsupported_claims",
        "splunk_search_duration_ms",
        "investigation_duration_ms",
    ):
        print(f"  {key}={agent.get(key)}")
    total_ms = int((time.monotonic() - total_started) * 1000)
    print(f"  total_probe_duration_ms={total_ms}")
    splunk_ok = splunk.get("status") == "OK" and int(splunk.get("event_count") or 0) > 0
    agent_ok = int(agent.get("splunk_tool_calls") or 0) >= 1 and int(agent.get("splunk_events") or 0) > 0
    agent_status_ok = str(agent.get("splunk_status") or "") in {
        "SUCCESS_WITH_RESULTS",
        "SPLUNK_RESULT_TRUNCATED",
    }
    return 0 if splunk_ok and agent_ok and agent_status_ok else 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--splunk-only", action="store_true")
    args = parser.parse_args()
    try:
        code = asyncio.run(_main(args))
    except ImportError as exc:
        print(f"Import error: {exc}")
        sys.exit(2)
    sys.exit(code)


if __name__ == "__main__":
    main()
