"""Test that automation rule subject_fields includes all allowed fields."""

from types import SimpleNamespace

from app.services.runbook.condition_eval import _ALLOWED_FIELDS
from app.services.runbook.rule_executor import alert_subject_fields


def test_subject_fields_completeness_for_alerts():
    """
    Regression test: the executor's subject dict must carry every field
    ``condition_eval._ALLOWED_FIELDS`` permits for alert conditions.

    This prevents silent rule match failures when conditions reference fields
    that were never put in subject_fields at the call site.

    The dict is read from the real function rather than restated here: both
    writers now go through it (the rule evaluator worker for ``alert.created``,
    the alert PATCH endpoint for ``alert.updated``), and a hand-maintained copy
    is exactly how the rule preview panel once drifted from the executor.
    """
    subject_fields_passed = set(alert_subject_fields(SimpleNamespace()).keys())

    # _ALLOWED_FIELDS defines which fields conditions may reference
    allowed = _ALLOWED_FIELDS

    # Every allowed field must be present in subject_fields, or condition
    # evaluation will silently fail when a rule references that field.
    missing = allowed - subject_fields_passed

    assert missing == set(), (
        f"subject_fields missing fields that conditions may reference: {missing}. "
        f"Add them to rule_executor.alert_subject_fields(); the rule evaluator "
        f"worker and the alert PATCH endpoint both pass its output through."
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
