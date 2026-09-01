"""SOC doc playbook runtime helpers."""

from .golden_mapping import (
    golden_playbook_mappings,
    load_golden_soc_playbook_map,
    missing_required_tactics,
    resolve_playbook_for_golden_case,
    tactics_covered_by_mappings,
    validate_golden_case_playbook,
)
from .soc_doc_playbooks import (
    coverage_table,
    load_soc_doc_playbooks,
    playbook_guidance_for_context,
    resolve_soc_doc_playbook,
    resolve_soc_doc_playbook_from_context,
)
from .soc_techniques import (
    min_techniques_per_tactic,
    min_total_techniques,
    resolve_playbook_id_by_technique,
    tactic_technique_coverage_table,
    tactics_with_insufficient_techniques,
    technique_coverage_table,
    validate_technique_manifest,
)

__all__ = [
    "coverage_table",
    "golden_playbook_mappings",
    "load_golden_soc_playbook_map",
    "load_soc_doc_playbooks",
    "min_techniques_per_tactic",
    "min_total_techniques",
    "missing_required_tactics",
    "playbook_guidance_for_context",
    "resolve_playbook_for_golden_case",
    "resolve_playbook_id_by_technique",
    "resolve_soc_doc_playbook",
    "resolve_soc_doc_playbook_from_context",
    "tactic_technique_coverage_table",
    "tactics_covered_by_mappings",
    "tactics_with_insufficient_techniques",
    "technique_coverage_table",
    "validate_golden_case_playbook",
    "validate_technique_manifest",
]
