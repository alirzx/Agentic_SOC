"""Persist and reuse Ambient Copilot "Explain this alert" output.

The contextual explainer (agents ``/api/v1/contextual``) produces high-quality
Markdown with ``## What this alert means`` / ``## Likely attacker behavior`` /
``## Suggested next steps``. That prose is valuable beyond the drawer:

* Case reports should quote it as the analyst-facing alert narrative.
* Investigate agents should treat Suggested next steps as investigation guidance.

Storage lives under ``alerts.enrichment_data["contextual_explanation"]`` so we
do not need a migration and can evolve the shape without locking a column.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

_ENRICHMENT_KEY = "contextual_explanation"
_MAX_MARKDOWN = 24_000
_MAX_STEPS = 12
_MAX_STEP_LEN = 400

_SECTION_RE = re.compile(r"^##\s+(.+?)\s*$")
_BULLET_RE = re.compile(r"^\s*(?:[-*]|\d+[.)])\s+(.+)$")


def parse_explanation_markdown(markdown: str) -> dict[str, Any]:
    """Split explain Markdown into sections and bullet next-steps."""
    text = (markdown or "").strip()
    sections: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []
    for line in text.splitlines():
        match = _SECTION_RE.match(line)
        if match:
            if current is not None:
                sections[current] = "\n".join(buf).strip()
            current = match.group(1).strip().lower()
            buf = []
            continue
        buf.append(line)
    if current is not None:
        sections[current] = "\n".join(buf).strip()

    next_blob = ""
    for key, value in sections.items():
        if "suggested next" in key or key.endswith("next steps"):
            next_blob = value
            break
    steps: list[str] = []
    for line in next_blob.splitlines():
        bullet = _BULLET_RE.match(line)
        if not bullet:
            continue
        step = " ".join(bullet.group(1).split()).strip()
        if step and step not in steps:
            steps.append(step[:_MAX_STEP_LEN])
        if len(steps) >= _MAX_STEPS:
            break
    if not steps and next_blob.strip():
        # Prose paragraph with no bullets — keep as a single guidance item.
        steps = [" ".join(next_blob.split())[:_MAX_STEP_LEN]]

    meaning = ""
    for key, value in sections.items():
        if "what this alert means" in key or key.startswith("what this"):
            meaning = value
            break

    return {
        "markdown": text[:_MAX_MARKDOWN],
        "sections": sections,
        "meaning": meaning[:2_000] if meaning else None,
        "suggested_next_steps": steps,
    }


def get_stored_explanation(alert: Any) -> dict[str, Any] | None:
    """Return the stored explanation dict, or ``None``."""
    extra = getattr(alert, "enrichment_data", None)
    if not isinstance(extra, dict):
        return None
    stored = extra.get(_ENRICHMENT_KEY)
    if not isinstance(stored, dict):
        return None
    markdown = stored.get("markdown")
    if not isinstance(markdown, str) or not markdown.strip():
        return None
    return stored


def build_explanation_record(
    markdown: str,
    *,
    model: str | None = None,
    source: str = "contextual_explain",
) -> dict[str, Any]:
    """Normalize LLM Markdown into the persisted enrichment payload."""
    parsed = parse_explanation_markdown(markdown)
    return {
        "markdown": parsed["markdown"],
        "meaning": parsed.get("meaning"),
        "suggested_next_steps": parsed.get("suggested_next_steps") or [],
        "model": (model or "").strip() or None,
        "source": source,
        "generated_at": datetime.now(UTC).isoformat(),
    }


def merge_explanation_into_enrichment(
    enrichment_data: dict[str, Any] | None,
    record: dict[str, Any],
) -> dict[str, Any]:
    """Return a copy of enrichment_data with the explanation record set."""
    base = dict(enrichment_data) if isinstance(enrichment_data, dict) else {}
    base[_ENRICHMENT_KEY] = record
    return base


def explanation_for_agents(alert: Any) -> dict[str, Any] | None:
    """Shape stored (or empty) explanation for Investigate ``raw_alert``."""
    stored = get_stored_explanation(alert)
    if not stored:
        return None
    steps = stored.get("suggested_next_steps")
    if not isinstance(steps, list):
        steps = []
    clean_steps = [str(s).strip()[:_MAX_STEP_LEN] for s in steps if str(s).strip()][:_MAX_STEPS]
    return {
        "markdown": str(stored.get("markdown") or "")[:_MAX_MARKDOWN],
        "meaning": stored.get("meaning"),
        "suggested_next_steps": clean_steps,
        "model": stored.get("model"),
        "generated_at": stored.get("generated_at"),
        "source": stored.get("source") or "contextual_explain",
    }
