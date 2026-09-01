"""Tests for SOC doc playbooks (playbook/*.txt manifest integration)."""

from __future__ import annotations

import json
from pathlib import Path

from app.runtime.playbooks.golden_mapping import (
    missing_required_tactics,
    resolve_playbook_for_golden_case,
    validate_golden_case_playbook,
)
from app.runtime.playbooks.soc_doc_playbooks import (
    coverage_table,
    load_soc_doc_playbooks,
    resolve_soc_doc_playbook,
    resolve_soc_doc_playbook_from_context,
    _repo_root,
)
from app.runtime.playbooks.soc_techniques import (
    min_techniques_per_tactic,
    min_total_techniques,
    resolve_playbook_id_by_technique,
    tactic_technique_coverage_table,
    tactics_with_insufficient_techniques,
    technique_coverage_table,
    validate_technique_manifest,
)
from app.runtime.contracts import AgentContext, IncidentStateSnapshot

_GOLDEN_ROOT = Path(__file__).resolve().parent / "evaluation" / "golden"
_EXPECTED_TACTIC_PLAYBOOKS = 14


def _iter_golden_cases() -> list[dict]:
    cases: list[dict] = []
    for path in sorted(_GOLDEN_ROOT.glob("*.json")):
        if path.name == "manifest.json":
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and payload.get("id"):
            cases.append(payload)
    for path in sorted(_GOLDEN_ROOT.glob("*.jsonl")):
        if path.name.startswith("_"):
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if isinstance(payload, dict) and payload.get("id"):
                cases.append(payload)
    return cases


def test_manifest_loads_fourteen_tactics() -> None:
    rows = coverage_table()
    assert len(rows) == _EXPECTED_TACTIC_PLAYBOOKS
    mitre_ids = {r["mitre_id"] for r in rows}
    assert "TA0043" in mitre_ids
    assert "TA0042" in mitre_ids
    assert "TA0001" in mitre_ids
    assert "TA0009" in mitre_ids
    assert "TA0040" in mitre_ids


def test_source_txt_files_exist() -> None:
    root = _repo_root()
    for row in coverage_table():
        path = root / "playbook" / row["source_file"]
        assert path.is_file(), f"missing playbook file: {path}"


def test_resolve_by_attack_stage() -> None:
    pb = resolve_soc_doc_playbook(attack_stage="lateral_movement")
    assert pb is not None
    assert pb.mitre_id == "TA0008"
    assert pb.name == "Lateral Movement"


def test_resolve_reconnaissance_attack_stage() -> None:
    pb = resolve_soc_doc_playbook(attack_stage="reconnaissance")
    assert pb is not None
    assert pb.mitre_id == "TA0043"
    assert pb.id == "reconnaissance"


def test_resolve_resource_development_attack_stage() -> None:
    pb = resolve_soc_doc_playbook(attack_stage="resource_development")
    assert pb is not None
    assert pb.mitre_id == "TA0042"
    assert pb.id == "resource-development"


def test_resolve_collection_attack_stage() -> None:
    pb = resolve_soc_doc_playbook(attack_stage="collection")
    assert pb is not None
    assert pb.mitre_id == "TA0009"
    assert pb.id == "collection"


def test_resolve_by_classification_alias() -> None:
    pb = resolve_soc_doc_playbook(classification="credential_dumping")
    assert pb is not None
    assert pb.mitre_id == "TA0006"


def test_resolve_from_agent_context() -> None:
    ctx = AgentContext(
        incident_id="inc-1",
        tenant_id="tenant-1",
        objective="Investigate privilege escalation",
        state=IncidentStateSnapshot(
            raw_alert={"attack_stage": "privilege_escalation", "title": "UAC bypass"},
            severity="high",
        ),
        metadata={},
        evidence=[],
    )
    pb = resolve_soc_doc_playbook_from_context(ctx)
    assert pb is not None
    assert pb.id == "privilege-escalation"


def test_playbook_guidance_includes_splunk_hint() -> None:
    pb = resolve_soc_doc_playbook(attack_stage="execution")
    assert pb is not None
    guidance = pb.summary_for_llm()
    assert "splunk_search" in guidance
    assert "Execution" in guidance


def test_catalog_has_unique_ids() -> None:
    catalog = load_soc_doc_playbooks()
    ids = {pb.id for pb in catalog.values()}
    assert len(ids) == _EXPECTED_TACTIC_PLAYBOOKS


def test_technique_manifest_is_valid() -> None:
    errors = validate_technique_manifest()
    assert errors == [], f"technique manifest errors: {errors}"


def test_each_tactic_has_min_techniques() -> None:
    threshold = min_techniques_per_tactic()
    short = tactics_with_insufficient_techniques(threshold)
    assert short == {}, f"tactics below {threshold} techniques: {short}"


def test_technique_to_playbook_resolution() -> None:
    assert resolve_playbook_id_by_technique("T1530") == "collection"
    assert resolve_playbook_id_by_technique("T1059.001") == "execution"
    assert resolve_playbook_id_by_technique("T1059.003") == "execution"
    assert resolve_playbook_id_by_technique("T1595") == "reconnaissance"


def test_technique_coverage_meets_minimum_total() -> None:
    rows = technique_coverage_table()
    floor = min_total_techniques()
    assert floor >= 300
    assert len(rows) >= floor
    technique_ids = {r["technique_id"] for r in rows}
    assert len(technique_ids) == len(rows)


def test_every_technique_has_golden_case() -> None:
    rows = technique_coverage_table()
    missing = [r["technique_id"] for r in rows if not r.get("golden_case_id")]
    assert missing == [], f"{len(missing)} techniques without golden_case_id"


def test_all_required_tactics_covered_by_golden_map() -> None:
    assert missing_required_tactics() == []


def test_all_golden_cases_resolve_playbook() -> None:
    failures: list[str] = []
    for case in _iter_golden_cases():
        result = validate_golden_case_playbook(case)
        if not result["passed"]:
            failures.append(f"{case['id']}: {result}")
    assert failures == [], "\n".join(failures[:10])


def test_golden_case_resolves_via_technique_id() -> None:
    case = json.loads((_GOLDEN_ROOT / "insider_threat.json").read_text(encoding="utf-8"))
    pb_id, tactic = resolve_playbook_for_golden_case(case)
    assert pb_id == "collection"
    assert tactic == "TA0009"


def test_fourteen_tactics_in_technique_coverage() -> None:
    tactic_rows = tactic_technique_coverage_table()
    assert len(tactic_rows) == _EXPECTED_TACTIC_PLAYBOOKS
