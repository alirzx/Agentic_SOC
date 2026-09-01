#!/usr/bin/env python3
"""Generate soc_techniques_manifest.json from official MITRE ATT&CK Enterprise STIX.

Source: https://github.com/mitre/cti (enterprise-attack.json)
Enterprise v19.2 (Aug 2026): ~222 parent techniques + ~475 sub-techniques ≈ 697 total.

Selection policy (default target=300):
  1. Keep existing golden_case_id mappings from the current manifest.
  2. Include all parent techniques mapped to a SOC doc playbook tactic.
  3. Fill remaining slots with sub-techniques (sorted by technique_id) until target is met.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "playbooks" / "doc" / "soc_techniques_manifest.json"
TACTICS_PATH = REPO_ROOT / "playbooks" / "doc" / "soc_tactics_manifest.json"
ATTACK_CDN = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

TA_TO_PLAYBOOK: dict[str, str] = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
}


def load_playbook_tactics() -> dict[str, str]:
    """playbook_id -> mitre TA id (authoritative for validation)."""
    raw = json.loads(TACTICS_PATH.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for row in raw.get("playbooks") or []:
        if isinstance(row, dict) and row.get("id") and row.get("mitre_id"):
            out[str(row["id"])] = str(row["mitre_id"])
    return out


def fetch_attack_bundle(url: str = ATTACK_CDN) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_stix(bundle: dict[str, Any]) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Return (shortname->TA####, technique records)."""
    objects = bundle.get("objects") or []
    shortname_to_ta: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        shortname = str(obj.get("x_mitre_shortname") or "")
        ext = next(
            (r for r in obj.get("external_references") or [] if r.get("source_name") == "mitre-attack"),
            {},
        )
        ta_id = str(ext.get("external_id") or "")
        if shortname and ta_id:
            shortname_to_ta[shortname] = ta_id

    techniques: list[dict[str, Any]] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        ext = next(
            (r for r in obj.get("external_references") or [] if r.get("source_name") == "mitre-attack"),
            {},
        )
        tech_id = str(ext.get("external_id") or "").upper()
        if not tech_id:
            continue
        phases = [
            p.get("phase_name")
            for p in obj.get("kill_chain_phases") or []
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        tactic_ta: str | None = None
        for phase in phases:
            ta = shortname_to_ta.get(str(phase))
            if ta and ta in TA_TO_PLAYBOOK:
                tactic_ta = ta
                break
        if tactic_ta is None:
            for phase in phases:
                ta = shortname_to_ta.get(str(phase))
                if ta:
                    tactic_ta = ta
                    break
        playbook_id = TA_TO_PLAYBOOK.get(tactic_ta or "")
        if not playbook_id:
            continue
        techniques.append(
            {
                "technique_id": tech_id,
                "name": str(obj.get("name") or tech_id),
                "mitre_tactic_id": tactic_ta or "",
                "playbook_id": playbook_id,
                "is_subtechnique": "." in tech_id,
            }
        )
    techniques.sort(key=lambda r: r["technique_id"])
    return shortname_to_ta, techniques


def load_existing_golden_map() -> dict[str, str]:
    if not MANIFEST_PATH.is_file():
        return {}
    raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    golden: dict[str, str] = {}
    for row in raw.get("techniques") or []:
        if not isinstance(row, dict):
            continue
        tid = str(row.get("technique_id") or "").upper()
        gid = str(row.get("golden_case_id") or "").strip()
        if tid and gid:
            golden[tid] = gid
    return golden


def select_techniques(all_techniques: list[dict[str, Any]], target: int, golden: dict[str, str]) -> list[dict[str, Any]]:
    by_id = {t["technique_id"]: t for t in all_techniques}
    selected_ids: list[str] = []

    for tid in sorted(golden.keys()):
        if tid in by_id and tid not in selected_ids:
            selected_ids.append(tid)

    parents = [t["technique_id"] for t in all_techniques if not t["is_subtechnique"]]
    for tid in parents:
        if tid not in selected_ids:
            selected_ids.append(tid)

    subs = [t["technique_id"] for t in all_techniques if t["is_subtechnique"]]
    for tid in subs:
        if len(selected_ids) >= target:
            break
        if tid not in selected_ids:
            selected_ids.append(tid)

    selected_ids = selected_ids[:target]
    rows: list[dict[str, Any]] = []
    for tid in selected_ids:
        rec = dict(by_id[tid])
        gid = golden.get(tid, "")
        rows.append(
            {
                "technique_id": rec["technique_id"],
                "name": rec["name"],
                "mitre_tactic_id": rec["mitre_tactic_id"],
                "playbook_id": rec["playbook_id"],
                **({"golden_case_id": gid} if gid else {}),
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SOC techniques manifest from MITRE ATT&CK STIX")
    parser.add_argument("--target", type=int, default=300, help="Target technique count (default: 300)")
    parser.add_argument("--url", default=ATTACK_CDN, help="STIX bundle URL")
    parser.add_argument("--check", action="store_true", help="Validate counts only; do not write")
    args = parser.parse_args()

    playbook_tactics = load_playbook_tactics()
    for ta, pb in TA_TO_PLAYBOOK.items():
        if pb in playbook_tactics and playbook_tactics[pb] != ta:
            raise SystemExit(f"TA map mismatch: {ta} -> {pb} but playbook declares {playbook_tactics[pb]}")

    bundle = fetch_attack_bundle(args.url)
    shortname_to_ta, all_techniques = parse_stix(bundle)
    golden = load_existing_golden_map()
    selected = select_techniques(all_techniques, args.target, golden)

    parents = sum(1 for t in all_techniques if not t["is_subtechnique"])
    subs = len(all_techniques) - parents
    sel_parents = sum(1 for t in selected if "." not in t["technique_id"])
    sel_subs = len(selected) - sel_parents

    print(f"MITRE Enterprise STIX: {len(all_techniques)} mappable techniques ({parents} parent, {subs} sub)")
    print(f"Selected for manifest: {len(selected)} ({sel_parents} parent, {sel_subs} sub), target={args.target}")
    print(f"Tactics in STIX: {len(shortname_to_ta)}")

    if args.check:
        if len(selected) < args.target:
            raise SystemExit(f"Only {len(selected)} techniques available; target {args.target} not reachable")
        return

    payload = {
        "version": "2.0.0",
        "description": (
            "MITRE ATT&CK Enterprise technique → SOC doc playbook mapping. "
            f"Generated from official STIX bundle; {len(selected)} of ~{len(all_techniques)} mappable techniques."
        ),
        "source": {
            "name": "MITRE ATT&CK Enterprise",
            "stix_url": args.url,
            "enterprise_totals": {"parent_techniques": parents, "sub_techniques": subs, "mappable": len(all_techniques)},
        },
        "min_techniques_per_tactic": 4,
        "min_total_techniques": args.target,
        "techniques": selected,
    }
    MANIFEST_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {MANIFEST_PATH}")


if __name__ == "__main__":
    main()
