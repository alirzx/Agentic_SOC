"""Durable outcome-memory priors — close the loop (Wave 1).

Every triage outcome (autonomous OR human) is written back as a per-signature
prior, so a later alert with the same evidence signature can be auto-suppressed
instead of re-triaged. This is what makes alert volume actually shrink over
time: confirmed-benign signatures stop reaching the queue.

Honesty + safety:
* AI-authored priors are trusted less than human-verified ones. A human prior
  suppresses immediately; an AI prior only suppresses once it has been
  corroborated by repeat outcomes (``count``) at high confidence.
* Only auto-closeable dispositions (false_positive / benign / benign_true_positive)
  ever suppress. A prior true-positive never auto-closes a future alert.
* Human authorship is sticky: an AI prior that a human later overrode stays
  ``human`` and never downgrades.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import structlog

from app.agents.dispositions import AUTO_CLOSEABLE_DISPOSITIONS, normalize_disposition
from app.memory.institutional import institutional_get, institutional_set

logger = structlog.get_logger()

OUTCOME_KEY_PREFIX = "outcome:"
HUMAN = "human"
AI = "ai"

# Suppression gates for AI-authored priors (env-overridable). Human priors are
# always trusted; AI priors need corroboration.
_MIN_AI_COUNT = int(os.getenv("AISOC_MEMORY_MIN_AI_COUNT", "3"))
_AI_CONF_THRESHOLD = float(os.getenv("AISOC_MEMORY_AI_CONFIDENCE", "0.90"))


def outcome_key(signature: str) -> str:
    return f"{OUTCOME_KEY_PREFIX}{signature}"


async def record_outcome(
    tenant_id: str,
    signature: str,
    *,
    disposition: str,
    confidence: float,
    author: str = AI,
    alert_id: Any = None,
) -> dict[str, Any]:
    """Write/refresh the per-signature outcome prior. Best-effort (never raises)."""
    disposition = normalize_disposition(disposition, default="needs_review")
    key = outcome_key(signature)
    now = datetime.now(UTC).isoformat()

    prior = await institutional_get(tenant_id, key)
    if isinstance(prior, dict) and prior.get("disposition") == disposition:
        count = int(prior.get("count", 0)) + 1
        first_seen = prior.get("first_seen", now)
        # Human authorship is sticky and never downgraded to AI.
        if prior.get("author") == HUMAN:
            author = HUMAN
    else:
        count = 1
        first_seen = now

    value: dict[str, Any] = {
        "signature": signature,
        "disposition": disposition,
        "confidence": round(float(confidence or 0.0), 4),
        "author": author,
        "count": count,
        "first_seen": first_seen,
        "last_seen": now,
        "last_alert_id": str(alert_id) if alert_id else None,
    }
    try:
        await institutional_set(
            tenant_id,
            key,
            value,
            tags=["outcome_prior", disposition, author],
            analyst_override=(author == HUMAN),
        )
    except Exception as exc:  # noqa: BLE001 — memory write is best-effort
        logger.debug("outcome_memory.write_failed", signature=signature, error=str(exc))
    return value


async def lookup_prior(tenant_id: str, signature: str) -> dict[str, Any] | None:
    """Return the durable outcome prior for a signature, or None."""
    prior = await institutional_get(tenant_id, outcome_key(signature))
    return prior if isinstance(prior, dict) else None


def should_auto_suppress(
    prior: dict[str, Any] | None,
    *,
    min_ai_count: int = _MIN_AI_COUNT,
    ai_confidence: float = _AI_CONF_THRESHOLD,
) -> bool:
    """Decide whether a prior is trusted enough to auto-suppress a repeat alert."""
    if not isinstance(prior, dict):
        return False
    disposition = str(prior.get("disposition", ""))
    if disposition not in AUTO_CLOSEABLE_DISPOSITIONS:
        return False
    if prior.get("author") == HUMAN:
        return True
    # AI-authored: require corroboration by repeat count + high confidence.
    return int(prior.get("count", 0)) >= min_ai_count and float(prior.get("confidence", 0.0)) >= ai_confidence


async def record_analyst_feedback(
    tenant_id: str,
    signature: str,
    *,
    feedback: str,  # 'good' or 'poor'
    alert_id: Any = None,
) -> dict[str, Any]:
    """Record analyst feedback on an AI verdict and update the outcome prior.

    Called from the Runbook UI when an analyst completes a needs_review task.
    - feedback='good': increment confidence, mark as human-verified
    - feedback='poor': decrement confidence or flag for review

    This is the feedback loop that trains the model: the next time a similar
    alert arrives, the prior's confidence is updated based on human feedback.
    """
    key = outcome_key(signature)
    now = datetime.now(UTC).isoformat()

    prior = await institutional_get(tenant_id, key)
    if not isinstance(prior, dict):
        # No prior yet (shouldn't happen on a needs_review, but safety measure)
        return {}

    disposition = prior.get("disposition", "needs_review")
    confidence = float(prior.get("confidence", 0.5))

    # Adjust confidence based on analyst feedback
    if feedback == "good":
        # AI was correct — increase confidence and mark as human-verified
        confidence = min(0.99, confidence + 0.05)  # Cap at 99%
        author = HUMAN  # Human verification is sticky
    elif feedback == "poor":
        # AI was incorrect — decrease confidence
        confidence = max(0.01, confidence - 0.10)  # Floor at 1%
        author = prior.get("author", AI)  # Keep original author
    else:
        # Unknown feedback — skip
        return prior

    # Update the prior with analyst feedback
    updated_prior: dict[str, Any] = {
        "signature": signature,
        "disposition": disposition,
        "confidence": round(confidence, 4),
        "author": author,
        "count": int(prior.get("count", 0)) + 1,
        "first_seen": prior.get("first_seen", now),
        "last_seen": now,
        "last_alert_id": str(alert_id) if alert_id else prior.get("last_alert_id"),
        "last_analyst_feedback": feedback,  # Record which feedback type
    }

    try:
        await institutional_set(
            tenant_id,
            key,
            updated_prior,
            tags=["outcome_prior", disposition, author, f"feedback_{feedback}"],
            analyst_override=(author == HUMAN),
        )
        logger.info(
            "outcome_memory.analyst_feedback_recorded",
            signature=signature,
            feedback=feedback,
            new_confidence=confidence,
        )
    except Exception as exc:  # noqa: BLE001 — memory write is best-effort
        logger.warning(
            "outcome_memory.feedback_write_failed",
            signature=signature,
            error=str(exc),
        )

    return updated_prior
