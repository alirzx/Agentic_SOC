"""Internal client for tenant-scoped agents-service calls.

Only the calls that must cross the service boundary live here. Today that is
analyst outcome feedback: the API owns the analyst session, the agents service
owns outcome memory, and writing another service's table directly would break
the ownership boundary the rest of the platform keeps.

Authentication reuses the agents service's existing HMAC tenant header
(``X-Tenant-Id`` + ``X-AiSOC-Tenant-Signature``, verified by
``app.privacy.tenant.resolve_request_tenant``). There is no user JWT on this
path, and the signing key is shared through ``AISOC_AGENTS_TENANT_SIGNING_KEY``.

Failure posture: best-effort. The caller has already committed its own write, so
a transport error is reported (``False``) and logged, never raised.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any, NamedTuple

import httpx
import structlog

from app.core.config import settings

logger = structlog.get_logger()

# Mirrors ``services/agents/app/privacy/tenant.py``. The prefix and header names
# are part of the wire contract between the two services; changing one without
# the other silently downgrades every call to 401.
_SIGNATURE_VERSION = b"aisoc-agents-tenant-v1"
_TENANT_HEADER = "X-Tenant-Id"
_SIGNATURE_HEADER = "X-AiSOC-Tenant-Signature"


def _agents_base_url() -> str:
    """Same resolution order as ``app.api.v1.endpoints.agents``."""
    return (
        os.getenv("AGENTS_SERVICE_URL")
        or os.getenv("AGENTS_API_URL")
        or "http://agents:8084"
    ).rstrip("/")


def sign_tenant(tenant_id: str, key: str) -> str:
    """Return the HMAC-SHA256 tenant signature the agents service expects."""
    message = _SIGNATURE_VERSION + b":" + str(tenant_id).strip().encode()
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


async def post_outcome_feedback(
    *,
    tenant_id: str,
    signature: str,
    feedback: str,
    alert_id: str | None = None,
) -> bool:
    """Send analyst feedback to the agents service.

    Returns ``True`` only when the agents service confirms a prior was updated.
    Returns ``False`` (without raising) when the call is not configured, the
    transport fails, or there is no prior to update.
    """
    signing_key = (settings.AGENTS_TENANT_SIGNING_KEY or "").strip()
    if not signing_key:
        # Fail closed: never send an unsigned tenant header.
        logger.info("agents_client.feedback_skipped", reason="no_signing_key")
        return False

    url = f"{_agents_base_url()}/api/v1/outcomes/feedback"
    payload = {"signature": signature, "feedback": feedback, "alert_id": alert_id}
    headers = {
        _TENANT_HEADER: str(tenant_id),
        _SIGNATURE_HEADER: sign_tenant(str(tenant_id), signing_key),
    }

    try:
        async with httpx.AsyncClient(timeout=settings.AGENTS_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        logger.warning("agents_client.feedback_transport_failed", error=str(exc))
        return False

    if response.status_code != 200:
        logger.warning(
            "agents_client.feedback_rejected",
            status=response.status_code,
        )
        return False

    try:
        return bool(response.json().get("updated"))
    except ValueError:
        logger.warning("agents_client.feedback_bad_response")
        return False


class PlaybookStart(NamedTuple):
    """Outcome of asking the agents service to start a playbook.

    ``run_id`` is set only when a run exists (a new one, or one the dedupe key
    matched). ``reason`` explains why nothing started. Callers record both in the
    ledger: a rule that names a playbook must always be able to say what
    happened to it.
    """

    run_id: str | None = None
    reason: str | None = None


def _clean_reason(value: Any, *, limit: int = 300) -> str | None:
    """One line, no control characters — this string reaches the ledger."""
    if value is None:
        return None
    text = " ".join(str(value).replace("\r", " ").replace("\n", " ").split())
    return text[:limit] or None


async def start_playbook_run(
    *,
    tenant_id: str,
    playbook_id: str,
    context: dict[str, Any],
    dry_run: bool = False,
    dedupe_key: str | None = None,
) -> PlaybookStart:
    """Start a playbook on the agents service on behalf of an automation rule.

    The rule has already passed the governance gate at this point; this call is
    the execution half. It is best-effort like the rest of the client: a transport
    error or a rejected request is returned as a reason, never raised, because the
    alert write it hangs off must not fail.

    ``trigger="automation_rule"`` lets the agents service refuse a start it
    cannot complete honestly — a playbook that would park at an approval step
    while ``AISOC_PLAYBOOK_RESUME`` is off answers 409 instead of stranding.
    """
    signing_key = (settings.AGENTS_TENANT_SIGNING_KEY or "").strip()
    if not signing_key:
        logger.info("agents_client.playbook_start_skipped", reason="no_signing_key")
        return PlaybookStart(reason="agents tenant signing key is not configured")

    if not _valid_playbook_id(playbook_id):
        return PlaybookStart(reason="linked playbook id is not a valid playbook id")

    url = f"{_agents_base_url()}/api/v1/playbooks/{playbook_id.strip()}/run"
    payload: dict[str, Any] = {
        "context": context,
        "dry_run": bool(dry_run),
        "trigger": "automation_rule",
    }
    if dedupe_key:
        payload["dedupe_key"] = str(dedupe_key)[:128]
    headers = {
        _TENANT_HEADER: str(tenant_id),
        _SIGNATURE_HEADER: sign_tenant(str(tenant_id), signing_key),
    }

    try:
        async with httpx.AsyncClient(timeout=settings.AGENTS_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        logger.warning("agents_client.playbook_start_transport_failed", error=str(exc))
        return PlaybookStart(reason=f"agents service unreachable: {_clean_reason(exc)}")

    if response.status_code not in (200, 202):
        detail = None
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = None
        logger.warning(
            "agents_client.playbook_start_rejected",
            status=response.status_code,
            playbook_id=playbook_id.strip(),
        )
        return PlaybookStart(
            reason=_clean_reason(detail) or f"agents service refused the run (HTTP {response.status_code})"
        )

    try:
        run_id = response.json().get("run_id")
    except ValueError:
        return PlaybookStart(reason="agents service returned an unreadable response")
    if not run_id:
        return PlaybookStart(reason="agents service returned no run id")
    return PlaybookStart(run_id=str(run_id))


_PLAYBOOK_ID_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _valid_playbook_id(playbook_id: str) -> bool:
    """Playbook ids are slugs; anything else never reaches a URL path."""
    return bool(_PLAYBOOK_ID_OK.match((playbook_id or "").strip()))


async def resume_playbook_run(
    *,
    tenant_id: str,
    run_id: str,
    decision: str,
    actor: str,
) -> bool:
    """Tell the agents service to release (or end) a parked playbook run.

    Returns ``True`` only when the agents service confirms the run moved past the
    gate. ``False`` — unconfigured, transport failure, 4xx/5xx, or a run that did
    not move — is recorded on the task as ``resume_applied = FALSE`` so the
    analyst sees "approved but not resumed" instead of a silent success.
    """
    signing_key = (settings.AGENTS_TENANT_SIGNING_KEY or "").strip()
    if not signing_key:
        logger.info("agents_client.resume_skipped", reason="no_signing_key")
        return False

    url = f"{_agents_base_url()}/api/v1/playbooks/runs/{run_id}/resume"
    payload = {"decision": decision, "actor": actor}
    headers = {
        _TENANT_HEADER: str(tenant_id),
        _SIGNATURE_HEADER: sign_tenant(str(tenant_id), signing_key),
    }

    try:
        async with httpx.AsyncClient(timeout=settings.AGENTS_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        logger.warning("agents_client.resume_transport_failed", error=str(exc))
        return False

    if response.status_code != 200:
        logger.warning(
            "agents_client.resume_rejected",
            status=response.status_code,
            run_id=str(run_id),
        )
        return False

    try:
        return bool(response.json().get("resumed"))
    except ValueError:
        logger.warning("agents_client.resume_bad_response")
        return False


async def list_playbooks(
    *,
    tenant_id: str,
) -> list[dict[str, Any]]:
    """Fetch all playbooks from the agents service for the given tenant.

    Returns a list of playbook objects with at least ``id``, ``name``, and
    ``description`` fields. Returns an empty list if the agents service is
    unreachable or returns an error.

    Unlike the other agent client functions, this call does NOT require a
    tenant signing key because playbooks are fetched without credentials.
    If a signing key is configured, we use it for consistency.
    """
    signing_key = (settings.AGENTS_TENANT_SIGNING_KEY or "").strip()
    url = f"{_agents_base_url()}/api/v1/playbooks"
    headers = {}
    if signing_key:
        headers[_TENANT_HEADER] = str(tenant_id)
        headers[_SIGNATURE_HEADER] = sign_tenant(str(tenant_id), signing_key)

    try:
        async with httpx.AsyncClient(timeout=settings.AGENTS_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        logger.warning("agents_client.list_playbooks_transport_failed", error=str(exc))
        return []

    if response.status_code != 200:
        logger.warning(
            "agents_client.list_playbooks_rejected",
            status=response.status_code,
        )
        return []

    try:
        playbooks = response.json()
        if not isinstance(playbooks, list):
            logger.warning("agents_client.list_playbooks_invalid_response", type=type(playbooks))
            return []
        # Extract only the fields we need for the UI dropdown
        return [
            {
                "id": pb.get("id", ""),
                "name": pb.get("name", "Untitled"),
                "description": pb.get("description", ""),
            }
            for pb in playbooks
            if pb.get("id")  # Skip any playbooks without an id
        ]
    except (ValueError, KeyError) as exc:
        logger.warning("agents_client.list_playbooks_parse_failed", error=str(exc))
        return []
