"""Format Ambient Copilot alert explanations for Investigate agent prompts.

When the console (or API proxy) has already run "Explain this alert", the
result is attached on ``raw_alert["contextual_explanation"]`` with Markdown
plus structured ``suggested_next_steps``. Recon / Forensic / Responder agents
append that block so they investigate with the same analyst grounding the
operator just saw — without re-asking the LLM for a second explanation.
"""

from __future__ import annotations

from typing import Any

from .prompt_sanitizer import sanitize_iterable_of_strings, sanitize_text

_MAX_MARKDOWN = 3_500
_MAX_STEPS = 10


def format_explanation_guidance(raw_alert: dict[str, Any] | None) -> str:
    """Return a prompt appendix, or ``\"\"`` when no explanation is present."""
    if not isinstance(raw_alert, dict):
        return ""
    expl = raw_alert.get("contextual_explanation")
    if not isinstance(expl, dict):
        return ""

    meaning = sanitize_text(str(expl.get("meaning") or ""), max_len=1_200)
    markdown = sanitize_text(str(expl.get("markdown") or ""), max_len=_MAX_MARKDOWN)
    steps_raw = expl.get("suggested_next_steps")
    steps = sanitize_iterable_of_strings(
        steps_raw if isinstance(steps_raw, list) else [],
        max_item_len=300,
        max_items=_MAX_STEPS,
    )
    if not meaning and not markdown and not steps:
        return ""

    lines = [
        "Analyst alert explanation (from Ambient Copilot — use as investigation guidance,",
        "not as proven facts):",
        "<UNTRUSTED_DATA>",
    ]
    if meaning:
        lines.extend(["What this alert means:", meaning, ""])
    elif markdown:
        lines.extend(["Explanation:", markdown, ""])
    if steps:
        lines.append("Suggested next steps to pursue:")
        for idx, step in enumerate(steps, start=1):
            lines.append(f"{idx}. {step}")
        lines.append("")
    lines.append("</UNTRUSTED_DATA>")
    return "\n".join(lines).strip()
