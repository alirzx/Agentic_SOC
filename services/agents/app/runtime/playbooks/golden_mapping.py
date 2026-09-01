"""Golden eval case ↔ SOC doc playbook mapping for CI tactic coverage."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from .soc_doc_playbooks import _repo_root, load_soc_doc_playbooks, resolve_soc_doc_playbook
from .soc_techniques import resolve_playbook_id_by_technique, technique_index


def _map_path() -> Path:
    return _repo_root() / "playbooks" / "doc" / "golden_soc_playbook_map.json"


@lru_cache(maxsize=1)
def load_golden_soc_playbook_map() -> dict[str, Any]:
    path = _map_path()
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def golden_playbook_mappings() -> list[dict[str, str]]:
    raw = load_golden_soc_playbook_map()
    rows = raw.get("mappings") or []
    return [r for r in rows if isinstance(r, dict)]


def required_mitre_tactics() -> list[str]:
    raw = load_golden_soc_playbook_map()
    tactics = raw.get("required_mitre_tactics") or []
    return [str(t) for t in tactics]


def tactics_covered_by_mappings() -> dict[str, list[str]]:
    """Return mitre_id -> list of golden_case_ids."""
    covered: dict[str, list[str]] = {}
    for row in golden_playbook_mappings():
        mitre_id = str(row.get("mitre_id") or "")
        case_id = str(row.get("golden_case_id") or "")
        if not mitre_id or not case_id:
            continue
        covered.setdefault(mitre_id, []).append(case_id)
    return covered


def missing_required_tactics() -> list[str]:
    covered = set(tactics_covered_by_mappings().keys())
    return [t for t in required_mitre_tactics() if t not in covered]


def _playbook_from_techniques(case: dict[str, Any]) -> tuple[str | None, str | None]:
    techniques = case.get("expected_techniques") or case.get("mitre_techniques") or []
    index = technique_index()
    for raw_tid in techniques:
        tid = str(raw_tid).strip().upper()
        playbook_id = resolve_playbook_id_by_technique(tid)
        if playbook_id:
            row = index.get(tid) or index.get(tid.split(".", 1)[0] if "." in tid else "")
            tactic = row.get("mitre_tactic_id") if row else None
            return playbook_id, tactic
    return None, None


def resolve_playbook_for_golden_case(case: dict[str, Any]) -> tuple[str | None, str | None]:
    """Resolve expected playbook_id and mitre_id from case fields or central map."""
    expected_id = case.get("expected_soc_doc_playbook_id")
    expected_mitre = case.get("expected_mitre_tactic_id")
    if expected_id:
        return str(expected_id), str(expected_mitre or "")
    case_id = str(case.get("id") or "")
    for row in golden_playbook_mappings():
        if str(row.get("golden_case_id")) == case_id:
            return str(row.get("playbook_id") or ""), str(row.get("mitre_id") or "")
    pb_id, tactic = _playbook_from_techniques(case)
    if pb_id:
        return pb_id, tactic
    attack_stage = case.get("attack_stage")
    pb = resolve_soc_doc_playbook(attack_stage=str(attack_stage or "") or None)
    if pb is not None:
        return pb.id, pb.mitre_id
    return None, None


def validate_golden_case_playbook(case: dict[str, Any]) -> dict[str, Any]:
    """Validate a golden case resolves to its declared SOC doc playbook."""
    playbook_id, mitre_id = resolve_playbook_for_golden_case(case)
    catalog = load_soc_doc_playbooks()
    pb = catalog.get(playbook_id or "")
    attack_stage = case.get("attack_stage")
    resolved = resolve_soc_doc_playbook(attack_stage=str(attack_stage or "") or None)
    expected_id = case.get("expected_soc_doc_playbook_id")
    expected_mitre = case.get("expected_mitre_tactic_id")
    passed = (
        playbook_id is not None
        and pb is not None
        and resolved is not None
        and resolved.id == playbook_id
    )
    if expected_id:
        passed = passed and playbook_id == str(expected_id)
    if expected_mitre:
        passed = passed and mitre_id == str(expected_mitre)
    techniques = case.get("expected_techniques") or case.get("mitre_techniques") or []
    technique_playbook_ok = True
    if not expected_id:
        for raw_tid in techniques:
            tid = str(raw_tid).strip().upper()
            mapped = resolve_playbook_id_by_technique(tid)
            if mapped and playbook_id and mapped != playbook_id:
                technique_playbook_ok = False
                break
    passed = passed and technique_playbook_ok
    return {
        "case_id": case.get("id"),
        "attack_stage": attack_stage,
        "expected_playbook_id": expected_id or playbook_id,
        "resolved_playbook_id": playbook_id,
        "resolved_mitre_id": mitre_id,
        "runtime_resolved_id": resolved.id if resolved else None,
        "passed": passed,
    }
