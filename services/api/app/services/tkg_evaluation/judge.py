"""Optional LLM judge over the frozen payload + attribution.

The rubric floor does not need this module. When a judge is wired in, it must
return strict JSON; anything else is rejected (``judge_invalid_output``) instead
of being coerced into a verdict. Parsing accepts a fenced ```json block and
nothing else — a model replying in prose is a bug to surface, not to guess at.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from app.services.tkg_evaluation.constants import VERDICTS

#: ``call_llm(messages) -> text`` — supplied by the caller so this package never
#: imports a provider client and tests can inject a fake.
LlmCall = Callable[[list[dict[str, str]]], Awaitable[str]]

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

SYSTEM_PROMPT = (
    "You are a SOC second-opinion reviewer. You receive a knowledge graph's TKG "
    "evidence about a set of alerts and must judge whether the alerts are one "
    "coordinated intrusion. Reply with ONE JSON object and nothing else."
)

_TEMPLATE = """Case: {title}
Alerts: {alert_count}

TKG attribution per alert:
{attribution}

Facts the graph returned for these alerts (synthetic facts are tagged):
{facts}

Return JSON with exactly these keys:
{{"verdict": "true_positive|likely_tp|needs_more_evidence|benign|insufficient",
  "confidence": 0-100,
  "reasons": ["short bullet", "..."]}}

Rules: cite only relations visible above; if the facts do not support a
conclusion say insufficient; do not exceed confidence 55 when every fact is
marked synthetic."""


def build_messages(payload: Mapping[str, Any], attribution: Mapping[str, Any]) -> list[dict[str, str]]:
    evidence_lines = []
    for envelope in (attribution or {}).get("alerts") or []:
        evidence_lines.append(
            "- {alert_id}: status={status} entity={entity} facts={facts} synthetic={synthetic} pass={pass}".format(
                alert_id=envelope.get("alert_id"),
                status=envelope.get("status"),
                entity=envelope.get("entity_id"),
                facts=envelope.get("facts"),
                synthetic=envelope.get("synthetic_facts"),
                **{"pass": envelope.get("pass")},
            )
        )
    fact_lines = []
    for fact in (payload or {}).get("facts") or []:
        if isinstance(fact, Mapping):
            fact_lines.append(
                f"- {fact.get('subject')} {fact.get('predicate')} {fact.get('object')}{' [synthetic]' if fact.get('synthetic') else ''}"
            )
    case = (payload or {}).get("case") or {}
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": _TEMPLATE.format(
                title=case.get("title") or "(untitled)",
                alert_count=case.get("alert_count") or 0,
                attribution="\n".join(evidence_lines) or "(none)",
                facts="\n".join(fact_lines[:60]) or "(no facts returned)",
            ),
        },
    ]


def parse_judge(text: str) -> dict[str, Any] | None:
    """Strictly parse a judge reply. ``None`` means "unusable", never a guess."""

    if not text:
        return None
    match = _FENCE.search(text)
    raw = match.group(1) if match else text
    try:
        data = json.loads(raw.strip())
    except (ValueError, AttributeError):
        return None
    if not isinstance(data, Mapping):
        return None
    verdict = str(data.get("verdict") or "").strip()
    if verdict not in VERDICTS:
        return None
    try:
        confidence = int(data.get("confidence") or 0)
    except (TypeError, ValueError):
        return None
    reasons = data.get("reasons")
    if isinstance(reasons, str):
        reasons = [reasons]
    if not isinstance(reasons, list):
        reasons = []
    return {
        "verdict": verdict,
        "confidence": max(0, min(confidence, 100)),
        "reasons": [str(reason)[:300] for reason in reasons[:8]],
    }


async def judge(payload: Mapping[str, Any], attribution: Mapping[str, Any], call_llm: LlmCall) -> dict[str, Any]:
    """Run the judge; never raises — a failure is reported as ``judged=None``."""

    messages = build_messages(payload, attribution)
    try:
        text = await call_llm(messages)
    except Exception as exc:  # noqa: BLE001 - judge failure must not fail the run
        return {"judged": None, "error": f"judge_unavailable: {exc.__class__.__name__}"}
    parsed = parse_judge(text)
    if parsed is None:
        return {"judged": None, "error": "judge_invalid_output"}
    return {"judged": parsed, "error": None}
