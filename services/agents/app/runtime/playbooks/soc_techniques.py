"""MITRE technique → SOC doc playbook mapping (soc_techniques_manifest.json)."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from .soc_doc_playbooks import _repo_root, load_soc_doc_playbooks

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _manifest_path() -> Path:
    return _repo_root() / "playbooks" / "doc" / "soc_techniques_manifest.json"


@lru_cache(maxsize=1)
def load_soc_techniques_manifest() -> dict[str, Any]:
    path = _manifest_path()
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def technique_rows() -> list[dict[str, str]]:
    raw = load_soc_techniques_manifest()
    rows = raw.get("techniques") or []
    return [r for r in rows if isinstance(r, dict) and r.get("technique_id")]


def min_techniques_per_tactic() -> int:
    raw = load_soc_techniques_manifest()
    return int(raw.get("min_techniques_per_tactic") or 4)


def min_total_techniques() -> int:
    raw = load_soc_techniques_manifest()
    return int(raw.get("min_total_techniques") or 0)


def technique_index() -> dict[str, dict[str, str]]:
    """technique_id -> row (playbook_id, mitre_tactic_id, name, golden_case_id)."""
    index: dict[str, dict[str, str]] = {}
    for row in technique_rows():
        tid = str(row.get("technique_id") or "").strip().upper()
        if not tid:
            continue
        index[tid] = {
            "technique_id": tid,
            "name": str(row.get("name") or tid),
            "mitre_tactic_id": str(row.get("mitre_tactic_id") or ""),
            "playbook_id": str(row.get("playbook_id") or ""),
            "golden_case_id": str(row.get("golden_case_id") or ""),
        }
    return index


def resolve_playbook_id_by_technique(technique_id: str) -> str | None:
    """Resolve playbook_id from a MITRE technique ID (supports parent fallback)."""
    tid = str(technique_id or "").strip().upper()
    if not tid or not _TECHNIQUE_ID_RE.match(tid):
        return None
    index = technique_index()
    if tid in index:
        return index[tid]["playbook_id"] or None
    if "." in tid:
        parent = tid.split(".", 1)[0]
        if parent in index:
            return index[parent]["playbook_id"] or None
    return None


def techniques_by_tactic() -> dict[str, list[dict[str, str]]]:
    """mitre_tactic_id -> list of technique rows."""
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in technique_index().values():
        tactic = row.get("mitre_tactic_id") or ""
        if not tactic:
            continue
        grouped.setdefault(tactic, []).append(row)
    for tactic in grouped:
        grouped[tactic].sort(key=lambda r: r["technique_id"])
    return grouped


def tactics_with_insufficient_techniques(min_per_tactic: int | None = None) -> dict[str, int]:
    """Return tactics below the minimum technique count threshold."""
    threshold = min_per_tactic if min_per_tactic is not None else min_techniques_per_tactic()
    grouped = techniques_by_tactic()
    short: dict[str, int] = {}
    for tactic, rows in grouped.items():
        if len(rows) < threshold:
            short[tactic] = len(rows)
    return short


def validate_technique_manifest() -> list[str]:
    """Return list of validation errors (empty if manifest is consistent)."""
    errors: list[str] = []
    catalog = load_soc_doc_playbooks()
    playbook_ids = {pb.id for pb in catalog.values() if hasattr(pb, "id")}
    seen: set[str] = set()
    for row in technique_rows():
        tid = str(row.get("technique_id") or "").strip().upper()
        if not _TECHNIQUE_ID_RE.match(tid):
            errors.append(f"invalid technique_id: {tid!r}")
            continue
        if tid in seen:
            errors.append(f"duplicate technique_id: {tid}")
        seen.add(tid)
        pb_id = str(row.get("playbook_id") or "")
        if pb_id not in playbook_ids:
            errors.append(f"{tid}: unknown playbook_id {pb_id!r}")
        tactic = str(row.get("mitre_tactic_id") or "")
        if pb_id in playbook_ids:
            pb = catalog.get(pb_id)
            if pb is not None and pb.mitre_id != tactic:
                errors.append(f"{tid}: tactic {tactic} != playbook {pb.mitre_id}")
    short = tactics_with_insufficient_techniques()
    for tactic, count in short.items():
        errors.append(f"{tactic}: only {count} techniques (min {min_techniques_per_tactic()})")
    total_min = min_total_techniques()
    if total_min and len(seen) < total_min:
        errors.append(f"total techniques {len(seen)} below min_total_techniques {total_min}")
    return errors


def technique_coverage_table() -> list[dict[str, str]]:
    """Flat table for reporting: technique, tactic, playbook, golden case."""
    rows: list[dict[str, str]] = []
    for row in sorted(technique_index().values(), key=lambda r: (r["mitre_tactic_id"], r["technique_id"])):
        rows.append(
            {
                "technique_id": row["technique_id"],
                "technique_name": row["name"],
                "mitre_tactic_id": row["mitre_tactic_id"],
                "playbook_id": row["playbook_id"],
                "golden_case_id": row.get("golden_case_id") or "",
            }
        )
    return rows


def tactic_technique_coverage_table() -> list[dict[str, Any]]:
    """Per-tactic summary: tactic_id, technique_count, technique_ids."""
    grouped = techniques_by_tactic()
    rows: list[dict[str, Any]] = []
    for tactic in sorted(grouped.keys()):
        techniques = grouped[tactic]
        rows.append(
            {
                "mitre_tactic_id": tactic,
                "technique_count": len(techniques),
                "technique_ids": [t["technique_id"] for t in techniques],
                "playbook_id": techniques[0]["playbook_id"] if techniques else "",
            }
        )
    return rows
