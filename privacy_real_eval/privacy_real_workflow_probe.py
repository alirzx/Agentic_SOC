#!/usr/bin/env python3
"""Production-like real-provider DLP evaluation harness for Agentic_SOC.

This script intentionally reuses the product's real agent workflows and the
central Privacy Gateway / safe LLM contract. It is designed to be launched by
run_real_dlp_eval.sh from the repository root.

Artifacts contain real tenant/SOC data. Keep the output directory private and
do not commit it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

TRACE_STAGE_NAMES = {
    "INTERNAL_INPUT",
    "PROVIDER_INPUT",
    "PROVIDER_RESPONSE",
    "LOCAL_RESPONSE",
}

_TEST_NAMESPACE = uuid.UUID("5f9d20d7-69db-4ba0-9f9f-05a6ff879d64")


def _json_default(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, uuid.UUID):
        return str(value)
    return str(value)


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True, default=_json_default) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _safe_route(url: str | None) -> str:
    if not url:
        return "provider-default"
    parsed = urlparse(url)
    host = parsed.hostname or "configured-host"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    suffix = "/v1" if parsed.path.rstrip("/").endswith("/v1") else "/..."
    return f"{parsed.scheme or 'https'}://{host}/...{suffix}"


def _read_jsonish(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        raise ValueError(f"input file is empty: {path}")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        rows: list[Any] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON/JSONL at line {line_no}: {exc}") from exc
        if not rows:
            raise ValueError("input did not contain any JSON records")
        return rows


def _first_splunk_result(value: Any) -> dict[str, Any] | None:
    """Extract the first result from common Splunk export/search response shapes."""
    if isinstance(value, list):
        for item in value:
            candidate = _first_splunk_result(item)
            if candidate is not None:
                return candidate
        return None
    if not isinstance(value, dict):
        return None

    result = value.get("result")
    if isinstance(result, dict):
        return result

    results = value.get("results")
    if isinstance(results, list):
        for item in results:
            if isinstance(item, dict):
                return item

    # Already looks like an alert/notable record rather than a wrapper.
    if any(
        key in value
        for key in (
            "alert",
            "raw_alert",
            "title",
            "search_name",
            "rule_name",
            "orig_rule_title",
            "severity",
            "src_ip",
            "src",
            "host",
            "hostname",
        )
    ):
        return value
    return None


def _summary_from_alert(alert: dict[str, Any]) -> str:
    for key in (
        "title",
        "search_name",
        "rule_name",
        "orig_rule_title",
        "name",
        "message",
        "description",
        "signature",
    ):
        value = alert.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()[:2000]
    return "Real Splunk notable / alert for DLP evaluation"


def _normalise_payload(payload: Any, *, tenant_id: str, case_id: str | None) -> dict[str, Any]:
    splunk = _first_splunk_result(payload)
    if splunk is not None:
        payload = splunk

    if not isinstance(payload, dict):
        raise ValueError("input must resolve to a JSON object / Splunk result")

    if isinstance(payload.get("raw_alert"), dict):
        raw_alert = dict(payload["raw_alert"])
        summary = str(payload.get("alert_summary") or _summary_from_alert(raw_alert)).strip()
        resolved_case = str(case_id or payload.get("case_id") or raw_alert.get("id") or "dlp-real-eval")
    elif isinstance(payload.get("alert"), dict):
        raw_alert = dict(payload["alert"])
        # Preserve useful fused-envelope context without changing core alert fields.
        for key in ("confidence_score", "fusion_decision", "narrative", "alert_row_id"):
            if payload.get(key) is not None and key not in raw_alert:
                raw_alert[key] = payload[key]
        summary = str(payload.get("narrative") or _summary_from_alert(raw_alert)).strip()
        resolved_case = str(case_id or payload.get("case_id") or payload.get("id") or raw_alert.get("id") or "dlp-real-eval")
    else:
        raw_alert = dict(payload)
        summary = _summary_from_alert(raw_alert)
        resolved_case = str(case_id or raw_alert.get("case_id") or raw_alert.get("id") or "dlp-real-eval")

    return {
        "case_id": resolved_case,
        "tenant_id": tenant_id,
        "alert_summary": summary,
        "raw_alert": raw_alert,
    }


def _incident_uuid(case_id: str, raw_alert: dict[str, Any]) -> uuid.UUID:
    for candidate in (raw_alert.get("incident_id"), raw_alert.get("id"), case_id):
        if candidate is None:
            continue
        try:
            return uuid.UUID(str(candidate))
        except (ValueError, TypeError):
            continue
    return uuid.uuid5(_TEST_NAMESPACE, case_id)


class _TraceCaptureLogger:
    """Capture only Human Trace events without replacing application logging."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.events: list[dict[str, Any]] = []
        self.path.write_text("", encoding="utf-8")
        self.path.chmod(0o600)

    def info(self, event: str, *args: Any, **fields: Any) -> None:
        if not fields.get("human_trace"):
            return
        record = {"event": event, **fields}
        self.events.append(record)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, default=_json_default) + "\n")

    # Human Trace currently uses info only. These no-ops make the replacement
    # resilient if that module later emits a warning/debug message.
    def debug(self, *_args: Any, **_kwargs: Any) -> None:
        return

    def warning(self, *_args: Any, **_kwargs: Any) -> None:
        return

    def error(self, *_args: Any, **_kwargs: Any) -> None:
        return


def _install_trace_capture(path: Path) -> _TraceCaptureLogger:
    import app.llm.human_trace as human_trace

    capture = _TraceCaptureLogger(path)
    human_trace.logger = capture
    return capture


def _parse_trace_payload(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _group_trace_calls(events: list[dict[str, Any]], *, labels: list[str] | None = None) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for event in events:
        stage = str(event.get("stage") or "")
        if stage not in TRACE_STAGE_NAMES:
            continue
        if stage == "INTERNAL_INPUT" or current is None:
            if current is not None:
                calls.append(current)
            current = {
                "call_index": len(calls) + 1,
                "agent": None,
                "model": event.get("model"),
                "path": event.get("path"),
                "tenant_id": event.get("tenant_id"),
                "privacy_enabled": event.get("privacy_enabled"),
                "cache_hit": False,
            }
        current[stage.lower()] = _parse_trace_payload(event.get("payload"))
        current[f"{stage.lower()}_truncated"] = bool(event.get("payload_truncated"))
        if event.get("cache_hit"):
            current["cache_hit"] = True

    if current is not None:
        calls.append(current)

    if labels:
        for idx, call in enumerate(calls):
            if idx < len(labels):
                call["agent"] = labels[idx]
    return calls


def _audit_agent_labels(final_state: Any) -> list[str]:
    labels: list[str] = []
    audit_log = getattr(final_state, "audit_log", []) or []
    for entry in audit_log:
        kind = getattr(entry, "kind", None)
        kind_value = getattr(kind, "value", str(kind))
        if kind_value != "llm_prompt":
            continue
        agent = str(getattr(entry, "agent", "") or "").strip()
        if agent:
            labels.append(agent)
    return labels


def _audit_llm_events(final_state: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in getattr(final_state, "audit_log", []) or []:
        kind = getattr(entry, "kind", None)
        kind_value = getattr(kind, "value", str(kind))
        if kind_value not in {"llm_prompt", "llm_response"}:
            continue
        if hasattr(entry, "model_dump"):
            out.append(entry.model_dump(mode="json"))
        else:
            out.append(json.loads(json.dumps(entry, default=_json_default)))
    return out


async def _run_auto_triage(normalised: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    from app.agents.auto_triage_agent import run_auto_triage
    from app.models.state import AgentStatus, InvestigationState
    from app.privacy.context import privacy_context

    tenant_uuid = uuid.UUID(normalised["tenant_id"])
    state = InvestigationState(
        incident_id=_incident_uuid(normalised["case_id"], normalised["raw_alert"]),
        tenant_id=tenant_uuid,
        alert_summary=normalised["alert_summary"],
        raw_alert=normalised["raw_alert"],
        status=AgentStatus.PENDING,
    )

    trace_path = output_dir / "trace_auto_triage.jsonl"
    capture = _install_trace_capture(trace_path)
    with privacy_context(str(tenant_uuid)):
        final = await run_auto_triage(state)

    result = final.model_dump(mode="json")
    comparison = _group_trace_calls(capture.events, labels=["auto-triage"])
    _write_json(output_dir / "comparison_auto_triage.json", {"workflow": "auto-triage", "calls": comparison})
    _write_json(output_dir / "result_auto_triage.json", result)
    return {
        "workflow": "auto-triage",
        "status": result.get("status"),
        "verdict": result.get("verdict"),
        "confidence": result.get("confidence"),
        "trace_calls": len(comparison),
        "files": {
            "trace": trace_path.name,
            "comparison": "comparison_auto_triage.json",
            "result": "result_auto_triage.json",
        },
    }


async def _run_investigator(normalised: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    from app.investigator.orchestrator import InvestigatorOrchestrator

    trace_path = output_dir / "trace_investigator.jsonl"
    capture = _install_trace_capture(trace_path)
    orchestrator = InvestigatorOrchestrator()
    final = await orchestrator.run(
        case_id=normalised["case_id"],
        alert_summary=normalised["alert_summary"],
        raw_alert=normalised["raw_alert"],
        tenant_id=normalised["tenant_id"],
    )

    labels = _audit_agent_labels(final)
    comparison = _group_trace_calls(capture.events, labels=labels)
    result = final.model_dump(mode="json")
    audit_events = _audit_llm_events(final)

    _write_json(output_dir / "comparison_investigator.json", {"workflow": "investigator", "calls": comparison})
    _write_json(output_dir / "result_investigator.json", result)
    _write_json(output_dir / "investigator_llm_audit.json", audit_events)
    return {
        "workflow": "investigator",
        "status": result.get("status"),
        "error": result.get("error"),
        "trace_calls": len(comparison),
        "agent_labels": labels,
        "cost_summary": result.get("cost_summary", {}),
        "files": {
            "trace": trace_path.name,
            "comparison": "comparison_investigator.json",
            "result": "result_investigator.json",
            "llm_audit": "investigator_llm_audit.json",
        },
    }


def _validate_environment() -> None:
    required = {
        "OPENAI_BASE_URL": os.getenv("OPENAI_BASE_URL", "").strip(),
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", "").strip(),
        "AISOC_PRIVACY_TOKEN_KEY": os.getenv("AISOC_PRIVACY_TOKEN_KEY", ""),
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise RuntimeError("missing required runtime environment: " + ", ".join(missing))
    if len(required["AISOC_PRIVACY_TOKEN_KEY"].encode("utf-8")) < 32:
        raise RuntimeError("AISOC_PRIVACY_TOKEN_KEY must contain at least 32 bytes")
    if os.getenv("AISOC_LLM_PRIVACY_ENABLED", "0").strip().lower() not in {"1", "true", "yes", "on"}:
        raise RuntimeError("AISOC_LLM_PRIVACY_ENABLED must be enabled for this DLP evaluation")


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run real Agentic_SOC workflows through the real provider with DLP traces.")
    parser.add_argument("--input", required=True, type=Path, help="real alert/notable JSON or Splunk JSONL export")
    parser.add_argument("--tenant-id", required=True, help="canonical tenant UUID used for privacy isolation")
    parser.add_argument("--case-id", default=None, help="optional case/test id override")
    parser.add_argument("--workflow", choices=("auto-triage", "investigator", "both"), default="both")
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


async def _async_main(args: argparse.Namespace) -> int:
    _validate_environment()
    try:
        tenant_id = str(uuid.UUID(str(args.tenant_id).strip()))
    except (ValueError, TypeError) as exc:
        raise RuntimeError("--tenant-id must be the canonical tenant UUID") from exc

    if not args.input.is_file():
        raise RuntimeError(f"input file not found: {args.input}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.chmod(0o700)

    payload = _read_jsonish(args.input)
    normalised = _normalise_payload(payload, tenant_id=tenant_id, case_id=args.case_id)
    _write_json(args.output_dir / "input_snapshot.json", normalised)

    model_roles = {
        role: os.getenv(f"AISOC_MODEL_PIN_{role.upper().replace('-', '_')}", "")
        for role in ("triage", "recon", "investigation", "report", "summary", "copilot", "nl")
    }
    meta = {
        "provider_route": _safe_route(os.getenv("OPENAI_BASE_URL")),
        "models": model_roles,
        "privacy_enabled": os.getenv("AISOC_LLM_PRIVACY_ENABLED"),
        "human_trace_enabled": os.getenv("AISOC_LLM_HUMAN_TRACE_ENABLED"),
        "human_trace_max_chars": os.getenv("AISOC_LLM_HUMAN_TRACE_MAX_CHARS"),
        "stream_max_chars": os.getenv("AISOC_LLM_PRIVACY_STREAM_MAX_CHARS"),
        "response_cache_enabled": os.getenv("AISOC_LLM_RESPONSE_CACHE"),
        "deterministic": os.getenv("AISOC_DETERMINISTIC"),
        "skip_embeddings": os.getenv("AISOC_SKIP_EMBEDDINGS"),
        "tenant_id": tenant_id,
        "case_id": normalised["case_id"],
        "workflow": args.workflow,
        "input_file": str(args.input.resolve()),
        "note": "Artifacts contain real SOC data. Provider/API/privacy secrets are intentionally not recorded.",
    }
    _write_json(args.output_dir / "run_meta.json", meta)

    summary: dict[str, Any] = {
        "provider_route": meta["provider_route"],
        "tenant_id": tenant_id,
        "case_id": normalised["case_id"],
        "workflow": args.workflow,
        "runs": [],
    }

    if args.workflow in {"auto-triage", "both"}:
        print("\n=== REAL AUTO-TRIAGE / DLP TEST ===", flush=True)
        summary["runs"].append(await _run_auto_triage(normalised, args.output_dir))

    if args.workflow in {"investigator", "both"}:
        print("\n=== REAL INVESTIGATOR / DLP TEST ===", flush=True)
        summary["runs"].append(await _run_investigator(normalised, args.output_dir))

    _write_json(args.output_dir / "summary.json", summary)

    print("\n=== DLP REAL-WORKFLOW TEST COMPLETE ===")
    print(f"Provider route: {summary['provider_route']}")
    print(f"Tenant UUID:    {tenant_id}")
    print(f"Output:         {args.output_dir}")
    for run in summary["runs"]:
        print(f"- {run['workflow']}: status={run.get('status')} trace_calls={run.get('trace_calls')}")
        if run.get("verdict") is not None:
            print(f"  verdict={run.get('verdict')} confidence={run.get('confidence')}")
        if run.get("error"):
            print(f"  error={run.get('error')}")
    return 0


def main() -> int:
    try:
        return asyncio.run(_async_main(_args()))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level CLI needs actionable failure
        print(f"DLP REAL-WORKFLOW TEST FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
