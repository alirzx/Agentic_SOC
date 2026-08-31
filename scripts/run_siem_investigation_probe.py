#!/usr/bin/env python3
"""Run the dedicated SIEM-required golden case (Phase 8.7.2).

Usage::

    python scripts/run_siem_investigation_probe.py
    python scripts/run_siem_investigation_probe.py --splunk-only

Exit codes:
    0  SIEM investigation invoked splunk_search with live Splunk (if configured)
    1  Configuration, Splunk, or agent failure
    2  Import error
"""
from __future__ import annotations

import argparse
import asyncio
import sys
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

    config = load_splunk_config()
    desc = describe_splunk_config(config)
    out: dict[str, object] = {"config": desc}
    if not config.enabled or not config.password or not config.username:
        out["status"] = "CONFIGURATION_ERROR"
        return out
    client = SplunkClient(config)
    health = await client.health_check()
    out["health"] = health
    if health.get("status") != "HEALTHY":
        out["status"] = health.get("status")
        return out
    search_query = ensure_search_prefix("index=* | head 5")
    result = await run_splunk_search(search_query, earliest="-60m", latest="now", max_events=5)
    out["search_status"] = result.status
    out["sid"] = result.search_id
    out["event_count"] = result.event_count
    out["duration_ms"] = result.duration_ms
    out["truncated"] = result.truncated
    if result.events:
        sample = result.events[0]
        out["sample_evidence_id"] = sample.evidence_id
        out["sample_fields"] = sorted(sample.fields.keys())[:20]
        out["sample_host"] = sample.host
        out["sample_index"] = sample.index
        out["sample_sourcetype"] = sample.sourcetype
    no_result = await run_splunk_search(
        ensure_search_prefix("index=* aisoc_probe_no_match_xyz=impossible_value_12345"),
        earliest="-5m",
        max_events=5,
    )
    out["no_results_status"] = no_result.status
    out["status"] = "OK"
    return out


async def _run_agent_probe(timeout: float) -> dict[str, object]:
    from app.runtime.evaluation.service import AgenticEvaluationService

    svc = AgenticEvaluationService(timeout=timeout)
    run = await svc.run_evaluation("golden-siem", limit=1, write_reports=False)
    row = svc.get_cases(run.id)[0] if svc.get_cases(run.id) else None
    metrics = row.metric_details if row else {}
    inv_exec = metrics.get("investigation_execution") or {}
    tool_calls = row.tool_calls if row else []
    splunk_calls = [t for t in tool_calls if t.get("tool_name") == "splunk_search"]
    return {
        "run_id": run.id,
        "execution_mode": metrics.get("execution_mode"),
        "llm_calls": metrics.get("llm_calls", 0),
        "splunk_tool_calls": metrics.get("splunk_tool_calls", 0),
        "splunk_events": metrics.get("splunk_events", 0),
        "splunk_status": metrics.get("splunk_status"),
        "cost_status": run.cost_status,
        "cost": run.estimated_cost,
        "agentic_score": row.overall_score if row else None,
        "investigation_parse_status": inv_exec.get("parse_status"),
        "splunk_tool_call_records": splunk_calls,
    }


async def _main(args: argparse.Namespace) -> int:
    load_repo_dotenv()
    print("SIEM Investigation Probe (Phase 8.7.2)")
    print("----------------------------------------")
    splunk = await _splunk_live_probe()
    print()
    print("Splunk live:")
    cfg = splunk.get("config") or {}
    print(f"  password_present={cfg.get('password_present')}")
    print(f"  status={splunk.get('status')}")
    if splunk.get("health"):
        print(f"  health={splunk['health']}")
    if splunk.get("search_status"):
        print(f"  search_status={splunk.get('search_status')} sid={splunk.get('sid')} events={splunk.get('event_count')}")
        if splunk.get("sample_fields"):
            print(f"  sample_fields={splunk.get('sample_fields')}")
        print(f"  no_results_status={splunk.get('no_results_status')}")
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
    ):
        print(f"  {key}={agent.get(key)}")
    splunk_ok = splunk.get("status") == "OK"
    agent_ok = int(agent.get("splunk_tool_calls") or 0) >= 1
    return 0 if splunk_ok and agent_ok else 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=180.0)
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
