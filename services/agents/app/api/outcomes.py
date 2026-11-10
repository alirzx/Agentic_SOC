"""Internal outcome-feedback surface for the Runbook control plane.

Called by ``services/api`` when an analyst completes a Runbook manual task. This
path carries no user session: it is authenticated with the same HMAC-signed
tenant header every tenant-scoped agents call uses
(:func:`app.privacy.tenant.resolve_request_tenant`), so an unauthenticated
caller cannot write to another tenant's memory.

Honesty contract: the response reports whether a prior was actually updated. A
task whose alert has no recorded outcome prior returns ``updated: false`` — the
API logs that instead of claiming the model learned something.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.memory.outcomes import record_analyst_feedback
from app.privacy.tenant import resolve_request_tenant

router = APIRouter(prefix="/api/v1/outcomes", tags=["outcomes"])


class OutcomeFeedbackIn(BaseModel):
    signature: str = Field(min_length=1, max_length=200)
    feedback: Literal["good", "poor"]
    alert_id: str | None = None


@router.post("/feedback", summary="Apply analyst feedback to an outcome prior")
async def post_outcome_feedback(body: OutcomeFeedbackIn, request: Request) -> dict[str, bool]:
    tenant_id = resolve_request_tenant(request)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="authenticated tenant context required")

    prior = await record_analyst_feedback(
        tenant_id,
        body.signature.strip(),
        feedback=body.feedback,
        alert_id=body.alert_id,
    )
    return {"updated": bool(prior)}
