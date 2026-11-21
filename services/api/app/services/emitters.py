"""Domain event emitters for case lifecycle.

These are deliberately *in-band* writes (a system comment on the case) rather
than a message bus: the timeline is the audit surface analysts actually read,
and a broker outage must never make a persisted case look like it was never
created. A future event bus can subscribe from here without changing callers.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def emit_case_created_from_correlation(
    db: Any,
    *,
    case_id: uuid.UUID,
    tenant_id: uuid.UUID,
    campaign_key: str,
    score: int,
    normalizer_version: str,
    created: bool,
    observations: Sequence[Mapping[str, Any]] = (),
    entity_matches: Sequence[Mapping[str, Any]] = (),
) -> bool:
    """Append a system timeline entry describing the correlation bundle.

    Returns ``True`` when the comment was written. Failures are logged and
    swallowed: the case row is already committed and is the source of truth.
    """
    roles = sorted({str(o.get("role")) for o in observations if o.get("role")})
    entity_bits = ", ".join(
        f"{m.get('kind')}:{m.get('value')}" for m in entity_matches[:8] if m.get("value")
    )
    # Semantic versions read as ``v2.0.0``; a named origin such as
    # ``candidate-promotion`` must not be mangled into ``vcandidate-promotion``.
    version = str(normalizer_version or "").strip()
    normalizer_label = f"v{version}" if version[:1].isdigit() else version or "unknown"
    lines = [
        "Correlated by the graph correlation engine"
        if created
        else "Extended by the graph correlation engine",
        f"campaign_key: {campaign_key}",
        f"score: {score} (θ gate applied before submission)",
        f"normalizer: {normalizer_label}",
        f"observations: {len(observations)}",
        f"roles: {', '.join(roles) or 'n/a'}",
    ]
    if entity_bits:
        lines.append(f"shared entities: {entity_bits}")
    if observations:
        lines.append("timeline:")
        for observation in observations[:25]:
            lines.append(
                f"  - [{observation.get('role') or 'general'}] "
                f"{observation.get('observation_id')} "
                f"({observation.get('time_quality') or 'unknown'}, "
                f"{len(observation.get('alert_ids') or [])} alert(s))"
            )

    body = "\n".join(lines)[:8000]
    try:
        await db.execute(
            text(
                """
                INSERT INTO aisoc_case_comments
                    (id, case_id, tenant_id, author, body, is_system, created_at)
                VALUES
                    (:id, :case_id, :tenant_id, 'correlation-engine', :body, TRUE, :now)
                """
            ).bindparams(
                id=uuid.uuid4(),
                case_id=case_id,
                tenant_id=tenant_id,
                body=body,
                now=datetime.now(UTC),
            )
        )
        return True
    except Exception:  # noqa: BLE001 — timeline enrichment must never fail the request
        logger.warning(
            "emitters.correlation_comment_failed case=%s campaign=%s payload=%s",
            case_id,
            campaign_key,
            json.dumps({"score": score, "observations": len(observations)})[:200],
        )
        return False


__all__ = ["emit_case_created_from_correlation"]
