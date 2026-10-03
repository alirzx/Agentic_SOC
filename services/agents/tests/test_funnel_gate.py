"""Product funnel investigation gate + override prior bridge."""

from __future__ import annotations

from app.funnel.stages import SUPPRESSED, TRIAGED, passes_investigation_gate, stage_after_triage
from app.memory.override_priors import coarse_signature_key, should_suppress_from_override


def test_stage_after_triage():
    assert stage_after_triage(disposition="false_positive", auto_closed=True) == SUPPRESSED
    assert stage_after_triage(disposition="true_positive", auto_closed=False) == TRIAGED


def test_investigation_gate_policy():
    assert passes_investigation_gate(
        disposition="true_positive", severity="info", confidence=0.2
    )
    assert passes_investigation_gate(
        disposition="needs_review", severity="critical", confidence=0.1
    )
    assert passes_investigation_gate(
        disposition="needs_review", severity="medium", confidence=70
    )
    assert not passes_investigation_gate(
        disposition="needs_review", severity="medium", confidence=0.4
    )
    assert not passes_investigation_gate(
        disposition="benign", severity="critical", confidence=0.99
    )


def test_coarse_signature_key_stable():
    alert = {
        "category": "Identity",
        "connector_type": "Splunk",
        "mitre_techniques": ["t1110"],
        "severity": "High",
    }
    key_a = coarse_signature_key(alert)
    key_b = coarse_signature_key(
        {
            "category": "identity",
            "connector_type": "splunk",
            "mitre_techniques": ["T1110"],
            "severity": "high",
        }
    )
    assert key_a is not None
    assert key_a == key_b
    assert key_a.startswith("override:v2:")


def test_should_suppress_from_override_only_fp():
    assert should_suppress_from_override(
        {"corrected_verdict": "false_positive", "analyst_id": "u1", "author": "human"}
    )
    assert not should_suppress_from_override(
        {"corrected_verdict": "true_positive", "analyst_id": "u1", "author": "human"}
    )
    assert not should_suppress_from_override(None)
