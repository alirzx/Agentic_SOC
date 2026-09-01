"""Load SOC analyst doc playbooks (playbook/*.txt) for Agentic runtime guidance."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "playbook").is_dir() and (parent / "services").is_dir():
            return parent
    return here.parents[4]


_MANIFEST_PATH = _repo_root() / "playbooks" / "doc" / "soc_tactics_manifest.json"
_PLAYBOOK_TXT_DIR = _repo_root() / "playbook"
_MAX_GUIDANCE_CHARS = int(__import__("os").getenv("SOC_DOC_PLAYBOOK_MAX_CHARS", "2200"))


@dataclass(frozen=True)
class SocDocPlaybook:
    id: str
    name: str
    mitre_id: str
    attack_stages: tuple[str, ...]
    source_file: str
    initial_fields: tuple[str, ...]
    investigation_focus: tuple[str, ...]
    response_actions: tuple[str, ...]
    example_events: tuple[str, ...]
    source_path: Path

    def summary_for_llm(self) -> str:
        lines = [
            f"Playbook: {self.name} ({self.mitre_id})",
            "Workflow: Triage fields → FP/TP check → Investigation (process/cmdline/network) → IT validation → Response → Evidence/IOC → Restore",
            f"Initial review fields: {', '.join(self.initial_fields)}",
            f"Investigation focus: {'; '.join(self.investigation_focus)}",
            f"Response actions (shadow/eval: recommend only): {'; '.join(self.response_actions)}",
            f"Example event types: {', '.join(self.example_events)}",
            "Use splunk_search for SIEM telemetry when endpoint/process/auth/network evidence is required.",
        ]
        text = "\n".join(lines)
        if len(text) > _MAX_GUIDANCE_CHARS:
            return text[:_MAX_GUIDANCE_CHARS] + "…"
        return text


def _normalize_stage(value: str) -> str:
    return re.sub(r"[\s\-]+", "_", value.strip().lower())


@lru_cache(maxsize=1)
def load_soc_doc_playbooks() -> dict[str, SocDocPlaybook]:
    if not _MANIFEST_PATH.is_file():
        return {}
    raw = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    playbooks: dict[str, SocDocPlaybook] = {}
    for row in raw.get("playbooks") or []:
        if not isinstance(row, dict):
            continue
        pid = str(row.get("id") or "").strip()
        if not pid:
            continue
        source_file = str(row.get("source_file") or "")
        source_path = _PLAYBOOK_TXT_DIR / source_file
        pb = SocDocPlaybook(
            id=pid,
            name=str(row.get("name") or pid),
            mitre_id=str(row.get("mitre_id") or ""),
            attack_stages=tuple(str(s).strip().lower() for s in row.get("attack_stages") or []),
            source_file=source_file,
            initial_fields=tuple(str(f) for f in row.get("initial_fields") or []),
            investigation_focus=tuple(str(f) for f in row.get("investigation_focus") or []),
            response_actions=tuple(str(f) for f in row.get("response_actions") or []),
            example_events=tuple(str(f) for f in row.get("example_events") or []),
            source_path=source_path,
        )
        playbooks[pid] = pb
        for stage in pb.attack_stages:
            playbooks[_normalize_stage(stage)] = pb
    return playbooks


def resolve_soc_doc_playbook(
    *,
    attack_stage: str | None = None,
    classification: str | None = None,
    tags: list[str] | None = None,
) -> SocDocPlaybook | None:
    """Resolve analyst doc playbook by attack stage, classification, or tags."""
    catalog = load_soc_doc_playbooks()
    candidates = [attack_stage, classification]
    if tags:
        candidates.extend(tags)
    for raw in candidates:
        if not raw:
            continue
        key = _normalize_stage(str(raw))
        if key in catalog:
            return catalog[key]
        for stage_key, pb in catalog.items():
            if key in stage_key or stage_key in key:
                return pb
    if tags:
        from .soc_techniques import resolve_playbook_id_by_technique

        for tag in tags:
            pb_id = resolve_playbook_id_by_technique(str(tag))
            if pb_id and pb_id in catalog:
                return catalog[pb_id]
    return None


def resolve_soc_doc_playbook_from_context(context: Any) -> SocDocPlaybook | None:
    """Resolve playbook from AgentContext metadata and raw alert."""
    attack_stage = None
    classification = None
    tags: list[str] = []
    metadata = getattr(context, "metadata", {}) or {}
    triage = metadata.get("triage_result") or {}
    if isinstance(triage, dict):
        classification = triage.get("classification")
    state = getattr(context, "state", None)
    raw = getattr(state, "raw_alert", None) if state else None
    if isinstance(raw, dict):
        attack_stage = raw.get("attack_stage") or raw.get("attackStage")
        tags.extend([str(t) for t in raw.get("tags") or [] if t])
    entities = metadata.get("entities") or {}
    if isinstance(entities, dict) and entities.get("telemetry_type"):
        tags.append(str(entities["telemetry_type"]))
    return resolve_soc_doc_playbook(
        attack_stage=str(attack_stage or "") or None,
        classification=str(classification or "") or None,
        tags=tags,
    )


def playbook_guidance_for_context(context: Any) -> str | None:
    pb = resolve_soc_doc_playbook_from_context(context)
    if pb is None:
        return None
    return pb.summary_for_llm()


def coverage_table() -> list[dict[str, str]]:
    """Return MITRE tactic coverage rows for reporting."""
    seen: set[str] = set()
    rows: list[dict[str, str]] = []
    catalog = load_soc_doc_playbooks()
    for pb in catalog.values():
        if pb.id in seen:
            continue
        seen.add(pb.id)
        rows.append(
            {
                "playbook_id": pb.id,
                "mitre_tactic": pb.name,
                "mitre_id": pb.mitre_id,
                "source_file": pb.source_file,
                "example_events": "; ".join(pb.example_events),
            }
        )
    return sorted(rows, key=lambda r: r["mitre_id"])
