#!/usr/bin/env python3
"""Generate synthetic golden eval cases for MITRE techniques lacking golden_case_id.

Writes bulk cases to services/agents/tests/evaluation/golden/mitre_technique_coverage.jsonl
and patches playbooks/doc/soc_techniques_manifest.json + golden_soc_playbook_map.json.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "playbooks" / "doc" / "soc_techniques_manifest.json"
GOLDEN_MAP_PATH = REPO_ROOT / "playbooks" / "doc" / "golden_soc_playbook_map.json"
GOLDEN_ROOT = REPO_ROOT / "services" / "agents" / "tests" / "evaluation" / "golden"
JSONL_PATH = GOLDEN_ROOT / "mitre_technique_coverage.jsonl"

TA_ATTACK_STAGE: dict[str, str] = {
    "TA0043": "reconnaissance",
    "TA0042": "resource_development",
    "TA0001": "initial_access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege_escalation",
    "TA0005": "defense_evasion",
    "TA0006": "credential_access",
    "TA0007": "discovery",
    "TA0008": "lateral_movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command_and_control",
    "TA0040": "impact",
}

TA_SEVERITY: dict[str, str] = {
    "TA0043": "low",
    "TA0042": "medium",
    "TA0001": "high",
    "TA0002": "high",
    "TA0003": "medium",
    "TA0004": "high",
    "TA0005": "high",
    "TA0006": "critical",
    "TA0007": "low",
    "TA0008": "high",
    "TA0009": "medium",
    "TA0010": "high",
    "TA0011": "high",
    "TA0040": "critical",
}

TA_RESPONSE: dict[str, str] = {
    "TA0043": "investigate",
    "TA0042": "investigate",
    "TA0001": "isolate_host",
    "TA0002": "isolate_host",
    "TA0003": "investigate",
    "TA0004": "isolate_host",
    "TA0005": "investigate",
    "TA0006": "disable_account",
    "TA0007": "investigate",
    "TA0008": "isolate_host",
    "TA0009": "investigate",
    "TA0010": "block_indicator",
    "TA0011": "block_indicator",
    "TA0040": "isolate_host",
}


def technique_to_case_id(technique_id: str) -> str:
    return f"GOLDEN-{technique_id.replace('.', '-')}"


def load_handcrafted_technique_golden() -> dict[str, str]:
    """technique_id -> existing golden_case_id from hand-written JSON cases."""
    mapping: dict[str, str] = {}
    for path in sorted(GOLDEN_ROOT.glob("*.json")):
        if path.name == "manifest.json":
            continue
        case = json.loads(path.read_text(encoding="utf-8"))
        case_id = str(case.get("id") or "")
        if not case_id:
            continue
        for tid in case.get("expected_techniques") or case.get("mitre_techniques") or []:
            mapping[str(tid).upper()] = case_id
    return mapping


def build_case(row: dict[str, Any], case_id: str) -> dict[str, Any]:
    tactic = str(row["mitre_tactic_id"])
    tech = str(row["technique_id"])
    name = str(row["name"])
    playbook = str(row["playbook_id"])
    return {
        "id": case_id,
        "source": "SYNTHETIC",
        "title": f"{name} ({tech})",
        "description": f"Synthetic MITRE technique coverage case for {tech} — {name}.",
        "severity": TA_SEVERITY.get(tactic, "medium"),
        "response_class": TA_RESPONSE.get(tactic, "investigate"),
        "expected_techniques": [tech],
        "expected_actions": [TA_RESPONSE.get(tactic, "investigate")],
        "attack_stage": TA_ATTACK_STAGE.get(tactic, "investigation"),
        "expected_soc_doc_playbook_id": playbook,
        "expected_mitre_tactic_id": tactic,
        "template_id": "mitre_technique_coverage_v1",
        "telemetry": [{"source": "synthetic", "technique": tech, "technique_name": name}],
    }


def regenerate_golden_map(techniques: list[dict[str, Any]]) -> None:
    tactics = sorted({str(t["mitre_tactic_id"]) for t in techniques})
    mappings: list[dict[str, str]] = []
    for row in techniques:
        gid = str(row.get("golden_case_id") or "")
        if not gid:
            continue
        golden_file = "mitre_technique_coverage.jsonl"
        for path in GOLDEN_ROOT.glob("*.json"):
            if path.name == "manifest.json":
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("id") == gid:
                golden_file = path.name
                break
        mappings.append(
            {
                "golden_case_id": gid,
                "golden_file": golden_file,
                "playbook_id": str(row["playbook_id"]),
                "mitre_id": str(row["mitre_tactic_id"]),
                "technique_id": str(row["technique_id"]),
            }
        )
    payload = {
        "version": "2.0.0",
        "dataset_id": "golden-soc-playbook-v1",
        "description": "Maps golden eval cases to SOC doc playbooks and MITRE techniques for CI coverage",
        "required_mitre_tactics": tactics,
        "min_techniques_per_tactic": 4,
        "mappings": sorted(mappings, key=lambda m: (m["mitre_id"], m["technique_id"])),
    }
    GOLDEN_MAP_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    techniques: list[dict[str, Any]] = list(raw.get("techniques") or [])
    handcrafted = load_handcrafted_technique_golden()

    bulk_cases: list[dict[str, Any]] = []
    generated = 0
    preserved = 0

    for row in techniques:
        tid = str(row["technique_id"]).upper()
        existing = str(row.get("golden_case_id") or "").strip()
        if existing:
            preserved += 1
            continue
        case_id = handcrafted.get(tid) or technique_to_case_id(tid)
        row["golden_case_id"] = case_id
        if tid not in handcrafted:
            bulk_cases.append(build_case(row, case_id))
            generated += 1
        else:
            preserved += 1

    JSONL_PATH.write_text(
        "\n".join(json.dumps(c, ensure_ascii=False) for c in bulk_cases) + ("\n" if bulk_cases else ""),
        encoding="utf-8",
    )

    raw["techniques"] = techniques
    MANIFEST_PATH.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    regenerate_golden_map(techniques)

    manifest_meta = {
        "datasetId": "golden-benchmark-v1",
        "version": "2.0",
        "source": "SYNTHETIC",
        "cases": len(techniques),
        "handcrafted_json_cases": len(list(GOLDEN_ROOT.glob("*.json"))) - 1,
        "bulk_jsonl_cases": generated,
    }
    (GOLDEN_ROOT / "manifest.json").write_text(json.dumps(manifest_meta, indent=2) + "\n", encoding="utf-8")

    missing = [t for t in techniques if not t.get("golden_case_id")]
    print(f"Techniques total: {len(techniques)}")
    print(f"Preserved handcrafted mappings: {preserved}")
    print(f"Generated jsonl cases: {generated}")
    print(f"Wrote {JSONL_PATH}")
    print(f"Missing golden after run: {len(missing)}")
    if missing:
        raise SystemExit("Some techniques still lack golden_case_id")


if __name__ == "__main__":
    main()
