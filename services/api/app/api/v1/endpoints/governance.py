"""
Governance check endpoint for playbook step approval queries.

Phase 3: Governance Hardening

Agents service calls this endpoint to determine whether a playbook step
requires L2/L3/L4 approval before execution.

Endpoint: POST /api/v1/governance/check
Headers:
    X-Tenant-Id: tenant UUID (required)
    X-AiSOC-Tenant-Signature: HMAC-SHA256 if configured (optional)

Request:
    {
        "alert_id": "<uuid>",
        "action_slug": "isolate_host",
        "severity": "critical",
        "confidence": 85
    }

Response:
    {
        "decision": "approved" | "requires_approval" | "blocked" | "error",
        "governance_level": "L1" | "L2" | "L3" | "L4",
        "reason": "Severity 'critical' + confidence 85 = L3 escalation required",
        "requires_approval": true,
        "approved": false,
        "error": null
    }

This module is designed as a standalone addition to the existing runbook.py
endpoints, but can be imported into that router if preferred.
"""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, require_permission
from app.services.governance import query_autonomy_policy

logger = logging.getLogger("aisoc.api.governance")

router = APIRouter(prefix="/governance", tags=["governance"])

__all__ = ["router"]


class GovernanceCheckRequest(BaseModel):
    """Request to check governance policy for a playbook action."""

    alert_id: str | UUID = Field(..., description="Alert UUID driving the playbook")
    action_slug: str = Field(..., description="Action to check (e.g., isolate_host)")
    severity: str = Field(..., description="Alert severity (info|low|medium|high|critical)")
    confidence: int = Field(..., ge=0, le=100, description="Fusion confidence (0-100)")


class GovernanceCheckResponse(BaseModel):
    """Response from governance check."""

    decision: str = Field(
        ...,
        description="approved | requires_approval | blocked | error",
    )
    governance_level: str | None = Field(
        None,
        description="L1 | L2 | L3 | L4 or None if error",
    )
    reason: str = Field(
        ...,
        description="Human-readable explanation of the decision",
    )
    requires_approval: bool = Field(
        ...,
        description="True if L2/L3/L4 approval is needed",
    )
    approved: bool = Field(
        ...,
        description="True if action can proceed without approval",
    )
    error: str | None = Field(
        None,
        description="Error details if decision is 'error'",
    )


@router.post("/check", summary="Check governance policy for a playbook action")
async def check_governance_policy(
    request: GovernanceCheckRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> GovernanceCheckResponse:
    """
    Query the autonomy policy to determine if a playbook action requires approval.

    This endpoint is called by the agents playbook engine to decide whether a
    step (e.g., isolate_host, block_ip) needs L2/L3/L4 approval before execution.

    Args:
        request: Governance check parameters (alert_id, action_slug, severity, confidence)
        current_user: Authenticated user (permission check: alerts:read)

    Returns:
        GovernanceCheckResponse with decision, governance_level, reason, etc.

    Error Handling:
        - Alert not found → 404 (not disclosed to preserve multi-tenancy)
        - Invalid action_slug → "decision: error" in response (fail-closed)
        - Policy service unavailable → "decision: error" (fail-closed)

    Tenant Isolation:
        - current_user.tenant_id scopes the alert lookup
        - Response only contains decision info, no sensitive alert data
    """

    try:
        alert_uuid = str(request.alert_id)

        # Query autonomy policy
        # This method lives in services/api/app/services/autonomy_policy.py
        # and consults the platform's L0-L4 policy configuration.
        decision = await query_autonomy_policy(
            tenant_id=current_user.tenant_id,
            alert_id=alert_uuid,
            action_slug=request.action_slug,
            severity=request.severity,
            confidence=request.confidence,
        )

        # Build response
        return GovernanceCheckResponse(
            decision=decision.get("decision", "error"),
            governance_level=decision.get("governance_level"),
            reason=decision.get("reason", ""),
            requires_approval=decision.get("requires_approval", False),
            approved=decision.get("approved", False),
            error=decision.get("error"),
        )

    except ValueError as exc:
        # Invalid input (e.g., malformed UUID)
        logger.warning(
            "governance.check_invalid_input",
            extra={
                "error": str(exc),
                "action": request.action_slug,
            },
        )
        return GovernanceCheckResponse(
            decision="error",
            governance_level=None,
            reason="Invalid request parameters",
            requires_approval=True,  # Fail-closed
            approved=False,
            error=str(exc),
        )

    except Exception as exc:
        # Unexpected error
        logger.exception(
            "governance.check_error",
            extra={
                "error": str(exc),
                "action": request.action_slug,
            },
        )
        return GovernanceCheckResponse(
            decision="error",
            governance_level=None,
            reason="Governance check failed",
            requires_approval=True,  # Fail-closed
            approved=False,
            error=str(exc),
        )
