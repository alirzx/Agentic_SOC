"""Turn connector-recorded provenance into ledger rows.

The Splunk connector learns things the API cannot: which query mode actually
ran, how many notables the window held, whether the LLM payload came from the
query or was assembled in Python, and which fidelity caveats apply. Connectors
have no database access (by design — ingest is the only write path), so they
attach that knowledge to the event as ``raw_event.runbook_provenance`` and the
API promotes it into ``runbook_events`` the first time someone looks at the
alert.

Why lazy promotion instead of ingest-time writes
------------------------------------------------
Ingest is a Go service on the hot path of every event; adding a second database
write there would cost the whole pipeline for a feature that only matters when a
human opens the alert. The promotion is idempotent (each row carries a
deterministic ``idempotency_key``), so a re-read — or two analysts reading at
once — cannot duplicate a step.

What this module refuses to do
------------------------------
It never invents provenance. If the connector did not record a block, nothing is
written and the alert's runbook starts empty with an explicit empty state. This
is the line that keeps the Runbook page from becoming another summary derived
from whatever fields happen to be present.
"""

from __future__ import annotations

import json
import uuid
from collections import deque
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.runbook.recorder import record_event

logger = structlog.get_logger()

__all__ = ["PROVENANCE_KEY", "find_provenance", "materialize_alert_provenance"]

PROVENANCE_KEY = "runbook_provenance"

# Bounded walk: a hostile or circular envelope must not turn a page load into an
# unbounded traversal. Mirrors the budget fusion uses when lifting llm_payload.
_MAX_WALK = 40
_WALK_KEYS = ("raw_event", "raw_data", "unmapped", "metadata", "raw", "event")

_MODE_LABELS = {
    "pipeline": "full Mission Control pipeline",
    "simple": "simple notable query",
    "auto": "auto-selected",
}


def _as_mapping(value: Any) -> dict[str, Any] | None:
    """Coerce a dict or a JSON-object string into a mapping."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text_value = value.strip()
        if not text_value.startswith("{"):
            return None
        try:
            parsed = json.loads(text_value)
        except (TypeError, ValueError):
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


def find_provenance(raw_event: Any) -> dict[str, Any] | None:
    """Locate ``runbook_provenance`` anywhere in a bounded envelope walk."""
    root = _as_mapping(raw_event)
    if root is None:
        return None

    direct = root.get(PROVENANCE_KEY)
    if isinstance(direct, dict):
        return direct

    queue: deque[Any] = deque(root[key] for key in _WALK_KEYS if key in root)
    visited = 0
    while queue and visited < _MAX_WALK:
        visited += 1
        node = _as_mapping(queue.popleft())
        if node is None:
            continue
        found = node.get(PROVENANCE_KEY)
        if isinstance(found, dict):
            return found
        for key in _WALK_KEYS:
            if key in node:
                queue.append(node[key])
    return None


def _mode_summary(provenance: dict[str, Any]) -> str:
    """One-line, honest description of how the data was acquired."""
    mode = str(provenance.get("query_mode") or "unknown")
    label = _MODE_LABELS.get(mode, mode)
    parts = [f"Query mode: {label}"]

    volume = provenance.get("notable_volume")
    threshold = provenance.get("threshold")
    if isinstance(volume, int) and isinstance(threshold, int):
        comparison = "above" if volume > threshold else "within"
        parts.append(f"{volume:,} notables {comparison} the {threshold:,} threshold")
    elif isinstance(volume, int):
        parts.append(f"{volume:,} notables in window")

    reason = provenance.get("reason")
    if reason == "pipeline_failed":
        parts.append("the full pipeline failed, so the simple query was used")
    elif reason == "volume_above_threshold":
        parts.append("selected automatically by volume")
    elif reason == "operator_configured":
        parts.append("configured by the operator on this connector")

    return " · ".join(parts)


async def materialize_alert_provenance(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    raw_event: Any,
) -> int:
    """Promote the connector's provenance block into ledger rows.

    Returns the number of rows written (0 when there is nothing to promote, the
    block was already promoted, or the Runbook is disabled).
    """
    provenance = find_provenance(raw_event)
    if not provenance:
        return 0

    already = (
        await db.execute(
            text(
                """
                SELECT 1 FROM runbook_events
                 WHERE tenant_id = :tenant_id
                   AND subject_type = 'alert'
                   AND subject_id = :alert_id
                   AND stage = 'ingest'
                 LIMIT 1
                """
            ).bindparams(tenant_id=tenant_id, alert_id=alert_id)
        )
    ).first()
    if already:
        return 0

    source = str(provenance.get("source") or "connector")
    written = 0

    row_id = await record_event(
        db,
        tenant_id=tenant_id,
        subject_type="alert",
        subject_id=alert_id,
        stage="ingest",
        kind="query_mode",
        summary=_mode_summary(provenance),
        detail=_detail_for(provenance),
        status="recorded",
        actor_type="connector",
        actor_label=source,
        output_payload=provenance,
        idempotency_key=f"ingest:{alert_id}:query_mode",
    )
    if row_id is not None:
        written += 1

    payload_source = provenance.get("llm_payload_source")
    if payload_source:
        caveats = provenance.get("caveats") or []
        summary = (
            "LLM evidence payload assembled from the query"
            if payload_source == "query"
            else "LLM evidence payload assembled in code from the returned fields"
        )
        if caveats:
            summary += f" ({len(caveats)} fidelity caveat(s))"
        payload_row = await record_event(
            db,
            tenant_id=tenant_id,
            subject_type="alert",
            subject_id=alert_id,
            stage="enrich",
            kind="llm_payload",
            summary=summary,
            detail=("Caveats: " + ", ".join(str(c) for c in caveats)) if caveats else None,
            status="recorded",
            actor_type="connector",
            actor_label=source,
            output_payload={"llm_payload_source": payload_source, "caveats": list(caveats)},
            idempotency_key=f"ingest:{alert_id}:llm_payload",
        )
        if payload_row is not None:
            written += 1

    if written:
        # The caller may be a read-only endpoint that never commits on its own
        # (unlike the lazy narrative fill, which owns its UPDATE); persist here
        # so the promotion is not lost when the request session closes.
        await db.commit()
        logger.info(
            "runbook.materialized_provenance",
            alert_id=str(alert_id),
            rows=written,
        )
    return written


def _detail_for(provenance: dict[str, Any]) -> str | None:
    """Expanded body: the raw provenance facts, human-readable."""
    lines: list[str] = []
    for key, label in (
        ("query_mode", "Mode"),
        ("reason", "Reason"),
        ("notable_volume", "Notables in window"),
        ("threshold", "Threshold"),
        ("fallback_from", "Fell back from"),
        ("search_name", "Search"),
    ):
        value = provenance.get(key)
        if value not in (None, ""):
            lines.append(f"{label}: {value}")
    if provenance.get("fallback_error"):
        lines.append(f"Failure: {provenance['fallback_error']}")
    return "\n".join(lines) or None
