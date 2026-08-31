"""Version and reproducibility metadata for evaluation runs (Phase 8.5)."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from app.llm.factory import resolve_base_url, resolve_model_alias

TOOL_VERSION = "soc-tools/v1"
PROMPT_VERSION = "agentic-soc-llm/v1"
AGENT_VERSION = "runtime/v2.0"
WORKFLOW_VERSION = "agentic-eval-v1.6"


def _hash_payload(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def collect_model_metadata() -> dict[str, Any]:
    base_url = resolve_base_url() or "UNKNOWN"
    provider = "UNKNOWN"
    if base_url != "UNKNOWN":
        provider = base_url.split("//")[1].split("/")[0] if "//" in base_url else base_url
    temperature = float(os.getenv("AISOC_EVAL_TEMPERATURE", os.getenv("AISOC_LLM_TEMPERATURE", "0.0")))
    max_tokens_raw = os.getenv("AISOC_EVAL_MAX_TOKENS", os.getenv("AISOC_LLM_MAX_TOKENS", ""))
    max_tokens: int | str = int(max_tokens_raw) if max_tokens_raw.isdigit() else "UNKNOWN"
    roles = ("triage", "investigation", "report", "decision")
    models = {role: resolve_model_alias(role) for role in roles}
    primary_model = models.get("triage", "UNKNOWN")
    llm_configured = base_url != "UNKNOWN" and bool(os.getenv("OPENAI_API_KEY", "").strip())
    return {
        "provider": provider,
        "model": primary_model,
        "model_version": os.getenv("AISOC_MODEL_VERSION", primary_model),
        "temperature": temperature,
        "max_tokens": max_tokens,
        "base_url": base_url,
        "llm_configured": llm_configured,
        "role_models": models,
        "agent_version": AGENT_VERSION,
        "workflow_version": WORKFLOW_VERSION,
        "prompt_version": PROMPT_VERSION,
        "tool_version": TOOL_VERSION,
    }


def collect_reproducibility(dataset: Any) -> dict[str, Any]:
    cases_blob = [c.get("id") or c.get("case_id") for c in dataset.cases]
    meta = collect_model_metadata()
    config_hash = _hash_payload(
        {
            "workflow": meta["workflow_version"],
            "prompt": meta["prompt_version"],
            "tool": meta["tool_version"],
            "model": meta["model"],
            "temperature": meta["temperature"],
            "base_url": meta["base_url"],
        }
    )
    dataset_hash = _hash_payload({"dataset_id": dataset.dataset_id, "version": dataset.version, "cases": cases_blob})
    seed = os.getenv("AISOC_EVAL_SEED", "UNKNOWN")
    nondeterministic = meta["llm_configured"] and meta["temperature"] > 0
    return {
        "random_seed": seed,
        "temperature": meta["temperature"],
        "configuration_hash": config_hash,
        "prompt_hash": _hash_payload(meta["prompt_version"]),
        "dataset_hash": dataset_hash,
        "reproducibility": "probabilistic" if nondeterministic else "deterministic",
    }
