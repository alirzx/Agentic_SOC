"""
Governance policy query service for playbook action approval checks.

Phase 3: Governance Hardening

This module provides the logic to determine whether a playbook action
(isolate_host, block_ip, etc.) requires L2/L3/L4 approval based on the
alert's severity and confidence, and the platform's autonomy policy.
"""

from __future__ import annotations

import logging
from typing import Any

from app.services.runbook.action_catalog import ACTIONS

logger = logging.getLogger("aisoc.services.governance")


async def query_autonomy_policy(
    tenant_id: str,
    alert_id: str,
    action_slug: str,
    severity: str,
    confidence: int,
) -> dict[str, Any]:
    """
    Query the autonomy policy to determine if a playbook action requires approval.

    This function consults the platform's L0-L4 autonomy thresholds and returns
    a governance decision based on the alert's severity and confidence.

    Args:
        tenant_id: Tenant UUID scoping the lookup
        alert_id: Alert UUID (for audit logging)
        action_slug: Action identifier (e.g., "isolate_host", "block_ip")
        severity: Alert severity (info|low|medium|high|critical)
        confidence: Confidence score (0-100)

    Returns:
        dict with keys:
            - decision: "approved" | "requires_approval" | "blocked" | "error"
            - governance_level: "L1" | "L2" | "L3" | "L4" or None if error
            - reason: Human-readable explanation
            - requires_approval: bool (True if L2/L3/L4 approval needed)
            - approved: bool (True if can proceed without approval)
            - error: str or None

    Governance Level Mapping:
        L1: Auto-approved (low severity + low confidence)
        L2: Requires review (medium severity OR medium confidence)
        L3: Requires escalation (high severity OR high confidence)
        L4: Critical (critical severity OR very high confidence)

    Fail-Closed Behavior:
        - Unknown actions → "error" with requires_approval=true
        - Invalid severity → "error" with requires_approval=true
    """

    # Validate action exists
    if action_slug not in ACTIONS:
        logger.warning(
            "governance.unknown_action",
            extra={
                "tenant_id": tenant_id,
                "alert_id": alert_id,
                "action_slug": action_slug,
            },
        )
        return {
            "decision": "error",
            "governance_level": None,
            "reason": f"Unknown action: {action_slug}",
            "requires_approval": True,  # Fail-closed
            "approved": False,
            "error": f"Action '{action_slug}' is not registered",
        }

    # Map severity to numeric priority (higher = more risky)
    severity_map = {
        "info": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }

    severity_level = severity_map.get(severity.lower(), 0)
    if severity_level == 0:
        logger.warning(
            "governance.invalid_severity",
            extra={
                "tenant_id": tenant_id,
                "alert_id": alert_id,
                "severity": severity,
            },
        )
        return {
            "decision": "error",
            "governance_level": None,
            "reason": f"Invalid severity: {severity}",
            "requires_approval": True,  # Fail-closed
            "approved": False,
            "error": f"Severity '{severity}' is not valid",
        }

    # Determine governance level based on severity + confidence
    # Simple heuristic: escalate if either severity or confidence is high

    if severity_level >= 5 or confidence >= 90:
        governance_level = "L4"
        requires_approval = True
        reason = f"Severity '{severity}' + confidence {confidence} = L4 critical escalation"
    elif severity_level >= 4 or confidence >= 75:
        governance_level = "L3"
        requires_approval = True
        reason = f"Severity '{severity}' + confidence {confidence} = L3 escalation"
    elif severity_level >= 3 or confidence >= 60:
        governance_level = "L2"
        requires_approval = True
        reason = f"Severity '{severity}' + confidence {confidence} = L2 review"
    else:
        governance_level = "L1"
        requires_approval = False
        reason = f"Severity '{severity}' + confidence {confidence} = L1 auto-approved"

    logger.info(
        "governance.check_result",
        extra={
            "tenant_id": tenant_id,
            "alert_id": alert_id,
            "action": action_slug,
            "level": governance_level,
            "requires_approval": requires_approval,
        },
    )

    return {
        "decision": "requires_approval" if requires_approval else "approved",
        "governance_level": governance_level,
        "reason": reason,
        "requires_approval": requires_approval,
        "approved": not requires_approval,
        "error": None,
    }
