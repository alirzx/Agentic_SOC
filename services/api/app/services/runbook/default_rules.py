"""Vendor-neutral automation rules, importable instead of auto-seeded.

These were ``DEFAULT_AUTOMATION_RULES`` in ``endpoints/runbook.py``: every tenant
that opened the Automation Rules page got all of them inserted, whether or not
the tenant had any telemetry they could match. Two consequences made that wrong:

* the rules page started out claiming seventeen configured automations nobody
  chose, several of them ``dry_run=False`` at ``L4`` — i.e. genuinely executing;
* nobody could tell an intended rule from an inherited one, so "why did this
  alert get tagged?" had no owner.

They now ship as the ``core-defaults`` pack (:mod:`app.services.runbook.packs`)
and are imported rule by rule, on purpose. Their conditions, autonomy ceilings,
``dry_run`` flags and priorities are copied verbatim from the seeded set: this
change moves *when* an operator gets a rule, not what the rule does.

Two rules target ``case.created`` — an inert trigger today (no code path emits
it). They are included so the pack is the complete legacy set, carry
``subject_type='case'`` so they can never evaluate against an alert, and are
marked **inert** in the rules list.
"""

from __future__ import annotations

from typing import Any

__all__ = ["CORE_DEFAULT_RULES"]

#: The legacy default rules, in their original order.
CORE_DEFAULT_RULES: tuple[dict[str, Any], ...] = (
    # ── Generic triage hygiene ────────────────────────────────────────────────
    {
        "name": "High-risk alerts -> tag",
        "description": "Tag medium/high severity alerts when they exceed the review threshold.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "severity", "op": "in", "value": ["high", "critical"]},
            {"field": "confidence", "op": "ge", "value": 70},
        ],
        "action_slug": "add_alert_tag",
        "action_params": {"tag": "high-risk"},
        "autonomy_level": "L2",
        "dry_run": True,
        "enabled": True,
        "priority": 10,
        "subject_type": "alert",
    },
    {
        "name": "Critical alerts -> case",
        "description": "Open a follow-up case for critical alerts so the investigation stays visible and governed.",
        "trigger_type": "alert.created",
        "conditions": [{"field": "severity", "op": "eq", "value": "critical"}],
        "action_slug": "create_case",
        "action_params": {"template": "critical-alert"},
        "autonomy_level": "L2",
        "dry_run": True,
        "enabled": True,
        "priority": 20,
        "subject_type": "alert",
    },
    {
        "name": "Low-confidence alert close",
        "description": "Dry-run close on low-confidence benign alerts after analyst review has ruled out risk.",
        "trigger_type": "alert.updated",
        "conditions": [
            {"field": "severity", "op": "in", "value": ["info", "low"]},
            {"field": "confidence", "op": "lt", "value": 35},
        ],
        "action_slug": "close_alert",
        "action_params": {"status": "closed"},
        "autonomy_level": "L1",
        "dry_run": True,
        "enabled": True,
        "priority": 30,
        "subject_type": "alert",
    },
    {
        "name": "Phishing subject -> tag",
        "description": "Apply a phishing tag when the alert title or description indicates a phishing lure.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "title", "op": "contains", "value": "phishing"},
            {"field": "severity", "op": "in", "value": ["medium", "high", "critical"]},
        ],
        "action_slug": "add_alert_tag",
        "action_params": {"tag": "phishing-lure"},
        "autonomy_level": "L2",
        "dry_run": True,
        "enabled": True,
        "priority": 40,
        "subject_type": "alert",
    },
    {
        "name": "Credential theft -> case",
        "description": "Escalate suspicious credential-related activity into a case for analyst review.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "title", "op": "contains", "value": "credential"},
            {"field": "source", "op": "eq", "value": "identity"},
        ],
        "action_slug": "create_case",
        "action_params": {"template": "credential-theft"},
        "autonomy_level": "L2",
        "dry_run": True,
        "enabled": True,
        "priority": 50,
        "subject_type": "alert",
    },
    {
        "name": "Privileged account risk -> tag",
        "description": "Highlight high-risk privileged-user events before the next review cycle.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "title", "op": "contains", "value": "privileged"},
            {"field": "confidence", "op": "ge", "value": 80},
        ],
        "action_slug": "add_alert_tag",
        "action_params": {"tag": "privileged-user"},
        "autonomy_level": "L2",
        "dry_run": True,
        "enabled": True,
        "priority": 60,
        "subject_type": "alert",
    },
    # ── Containment recommendations ───────────────────────────────────────────
    {
        "name": "Known malicious IP -> block",
        "description": "Prepare a containment decision for known malicious IP indicators.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "tags", "op": "array_contains", "value": "malicious-ip"},
            {"field": "confidence", "op": "ge", "value": 85},
        ],
        "action_slug": "block_ip",
        "action_params": {"reason": "malicious-ip-indicator"},
        "autonomy_level": "L3",
        "dry_run": True,
        "enabled": True,
        "priority": 70,
        "subject_type": "alert",
    },
    {
        "name": "Endpoint infection -> isolate",
        "description": "Trigger a host isolation recommendation for endpoint compromise indicators.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "category", "op": "eq", "value": "endpoint"},
            {"field": "severity", "op": "eq", "value": "high"},
            {"field": "confidence", "op": "ge", "value": 75},
        ],
        "action_slug": "isolate_host",
        "action_params": {"target_type": "host", "reason": "endpoint_compromise"},
        "autonomy_level": "L3",
        "dry_run": True,
        "enabled": True,
        "priority": 80,
        "subject_type": "alert",
    },
    {
        "name": "Suspicious file -> quarantine",
        "description": "Queue a quarantine recommendation for suspicious file-based executions.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "title", "op": "contains", "value": "ransomware"},
            {"field": "confidence", "op": "ge", "value": 80},
        ],
        "action_slug": "quarantine_file",
        "action_params": {"reason": "suspicious-file-execution"},
        "autonomy_level": "L3",
        "dry_run": True,
        "enabled": True,
        "priority": 90,
        "subject_type": "alert",
    },
    # ── Case-scoped rules (inert: nothing emits case.created yet) ─────────────
    {
        "name": "Case assignment follow-up",
        "description": "Assign open cases to the on-duty analyst queue when they remain unowned.",
        "trigger_type": "case.created",
        "conditions": [
            {"field": "status", "op": "eq", "value": "new"},
            {"field": "priority", "op": "ge", "value": 80},
        ],
        "action_slug": "assign_case",
        "action_params": {"owner": "oncall"},
        "autonomy_level": "L2",
        "dry_run": True,
        "enabled": True,
        "priority": 100,
        "subject_type": "case",
    },
    {
        "name": "Case comment on analyst escalation",
        "description": "Add an operational note when the case is escalated for higher-level review.",
        "trigger_type": "case.created",
        "conditions": [
            {"field": "status", "op": "eq", "value": "escalated"},
            {"field": "confidence", "op": "ge", "value": 70},
        ],
        "action_slug": "add_case_comment",
        "action_params": {"text": "Escalated for analyst review"},
        "autonomy_level": "L2",
        "dry_run": True,
        "enabled": True,
        "priority": 110,
        "subject_type": "case",
    },
    # ── Realistic SOC scenarios ───────────────────────────────────────────────
    {
        "name": "Auto-enrich network alerts",
        "description": "Automatically query threat intel for any new network alert to add context before the analyst sees it.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "category", "op": "eq", "value": "network"},
            {"field": "severity", "op": "in", "value": ["medium", "high", "critical"]},
        ],
        "action_slug": "lookup_ip",
        "action_params": {},
        "autonomy_level": "L4",
        "dry_run": False,
        "enabled": True,
        "priority": 5,
        "subject_type": "alert",
    },
    {
        "name": "Auto-close EICAR test files",
        "description": "Close alerts from the standard EICAR antivirus test file to suppress noise during scheduled scans.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "title", "op": "contains", "value": "EICAR"},
            {"field": "source", "op": "eq", "value": "Windows Defender"},
        ],
        "action_slug": "close_alert",
        "action_params": {"status": "closed", "reason": "eicar-test-suppressed"},
        "autonomy_level": "L4",
        "dry_run": False,
        "enabled": True,
        "priority": 15,
        "subject_type": "alert",
    },
    {
        "name": "Isolate host on ransomware TTP",
        "description": "Immediately queue a host isolation decision when ransomware behaviour (T1486) is confirmed at critical severity.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "title", "op": "contains", "value": "T1486"},
            {"field": "severity", "op": "eq", "value": "critical"},
        ],
        "action_slug": "isolate_host",
        "action_params": {"target_type": "host", "reason": "ransomware-T1486"},
        "autonomy_level": "L2",
        "dry_run": True,
        "enabled": True,
        "priority": 1,
        "subject_type": "alert",
    },
    {
        "name": "Lock account on impossible travel",
        "description": "Temporarily disable accounts showing impossible travel anomalies pending analyst verification.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "title", "op": "contains", "value": "Impossible Travel"},
            {"field": "severity", "op": "in", "value": ["high", "critical"]},
        ],
        "action_slug": "disable_user_account",
        "action_params": {"reason": "impossible-travel-anomaly"},
        "autonomy_level": "L2",
        "dry_run": True,
        "enabled": True,
        "priority": 2,
        "subject_type": "alert",
    },
    {
        "name": "Add TI context to case on indicator match",
        "description": "Add a system comment to the case with the matched threat actor profile when a threat-intel tag is present.",
        "trigger_type": "case.created",
        "conditions": [
            {"field": "tags", "op": "array_contains", "value": "threat_intel_match"},
        ],
        "action_slug": "add_case_comment",
        "action_params": {"text": "Threat intel match — see linked IOC record for actor attribution."},
        "autonomy_level": "L4",
        "dry_run": False,
        "enabled": True,
        "priority": 25,
        "subject_type": "case",
    },
    {
        "name": "Tag noisy endpoint rules for tuning",
        "description": "Mark high-volume process-access events with 'needs_tuning' so detection engineering can review them.",
        "trigger_type": "alert.created",
        "conditions": [
            {"field": "category", "op": "eq", "value": "endpoint"},
            {"field": "confidence_label", "op": "eq", "value": "low"},
        ],
        "action_slug": "add_alert_tag",
        "action_params": {"tag": "needs_tuning"},
        "autonomy_level": "L4",
        "dry_run": False,
        "enabled": True,
        "priority": 90,
        "subject_type": "alert",
    },
)
