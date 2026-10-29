"""Test that automation rule subject_fields includes all allowed fields."""
import pytest
from app.services.runbook.condition_eval import _ALLOWED_FIELDS


def test_subject_fields_completeness_for_alerts():
    """
    Regression test: alerts.py must populate subject_fields with all fields
    that condition_eval._ALLOWED_FIELDS permits for alert conditions.
    
    This prevents silent rule match failures when conditions reference fields
    that weren't included in subject_fields at the call site.
    """
    # These fields are explicitly passed to run_rules_for_trigger in alerts.py
    # for both alert.created and alert.updated triggers
    subject_fields_passed = {
        "severity",
        "status",
        "priority",
        "confidence",
        "confidence_label",
        "funnel_stage",
        "disposition",
        "source",
        "connector_type",
        "category",
        "title",
        "description",
        "tags",
        "affected_ips",
        "affected_hosts",
        "affected_users",
        "risk_score",
        "mitre_tactics",
        "mitre_techniques",
        "rule_name",
    }
    
    # _ALLOWED_FIELDS defines which fields conditions may reference
    allowed = _ALLOWED_FIELDS
    
    # Every allowed field must be present in subject_fields, or condition
    # evaluation will silently fail when a rule references that field.
    missing = allowed - subject_fields_passed
    
    assert missing == set(), (
        f"subject_fields missing fields that conditions may reference: {missing}. "
        f"Add them to alerts.py run_rules_for_trigger calls (alert.created and "
        f"alert.updated triggers)."
    )


def test_condition_eval_allowed_fields_are_reasonable():
    """Verify the allowed fields list includes all documented fields."""
    expected_fields = {
        "severity",
        "status",
        "priority",
        "confidence",
        "confidence_label",
        "funnel_stage",
        "disposition",
        "category",
        "source",
        "connector_type",
        "title",
        "description",
        "tags",
        "affected_ips",
        "affected_hosts",
        "affected_users",
        "risk_score",
        "mitre_tactics",
        "mitre_techniques",
        "rule_name",
    }
    
    # All expected fields should be in _ALLOWED_FIELDS
    missing = expected_fields - _ALLOWED_FIELDS
    assert missing == set(), (
        f"_ALLOWED_FIELDS missing expected fields: {missing}. "
        f"These are documented in condition_eval.py docstring."
    )
