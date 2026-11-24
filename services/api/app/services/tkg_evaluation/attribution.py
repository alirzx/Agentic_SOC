"""Attribute a case's alerts to TKG entities and facts.

Resolution is not one verdict: each alert either resolves to an entity with
real facts, resolves onto synthetic documents only, or does not resolve at all.
Collapsing those three into a single "found / not found" would let a demo graph
confirm a production case, which is exactly the failure this module prevents.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable, Mapping
from typing import Any

from app.services.tkg_evaluation.client import TkgClient, TkgError
from app.services.tkg_evaluation.constants import CONCURRENCY, R_BUDGET
from app.services.tkg_evaluation.rubric import passes_for_alert

logger = logging.getLogger(__name__)

_SYNTHETIC_FLAGS = ("synthetic", "is_synthetic", "synthetic_source")


def _truthy_marker(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "synthetic"}


def is_synthetic_fact(fact: Mapping[str, Any], synthetic_doc_ids: Iterable[str] = ()) -> bool:
    """True when a fact's evidence comes from a synthetic/seed document.

    Checks the documented markers first, then the document id, because a
    backfilled demo KB tags the document once rather than every derived fact.
    """

    for key in _SYNTHETIC_FLAGS:
        if key in fact and _truthy_marker(fact.get(key)):
            return True
    evidence = fact.get("evidence") if isinstance(fact.get("evidence"), Mapping) else {}
    for key in _SYNTHETIC_FLAGS:
        if key in evidence and _truthy_marker(evidence.get(key)):
            return True
    kind = str(fact.get("source_kind") or evidence.get("source_kind") or "").lower()
    if kind == "synthetic":
        return True

    document_id = fact.get("document_id") or evidence.get("document_id")
    if document_id and str(document_id) in {str(value) for value in synthetic_doc_ids}:
        return True
    return False


def _facts_of(context: Mapping[str, Any]) -> list[dict[str, Any]]:
    facts = context.get("facts")
    if isinstance(facts, list):
        return [fact for fact in facts if isinstance(fact, Mapping)]
    return []


async def _attribute_one(
    client: TkgClient,
    alert_id: str,
    *,
    synthetic_doc_ids: Iterable[str],
    context_limit: int,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "alert_id": alert_id,
        "status": "unresolved",
        "entity_id": None,
        "canonical_key": None,
        "facts": 0,
        "synthetic_facts": 0,
        "pass": "none",
        "error": None,
        "fact_samples": [],
        "limitations": [],
        "retrieval_status": None,
    }
    try:
        resolved = await client.resolve(alert_id)
    except TkgError as exc:
        envelope["error"] = exc.code
        return envelope

    candidates = resolved.get("candidates") or []
    candidate = candidates[0] if candidates else {}
    status = str(resolved.get("status") or "unknown")
    envelope["status"] = status
    if (status != "resolved" or len(candidates) != 1 or resolved.get("automatic") is False
            or candidate.get("has_conflict") or candidate.get("graph_conflict") or candidate.get("candidates_truncated")):
        return envelope
    envelope["entity_id"] = candidate.get("entity_id")
    envelope["canonical_key"] = candidate.get("canonical_key")

    if not envelope["entity_id"]:
        return envelope

    try:
        context = await client.context(str(envelope["entity_id"]), limit=context_limit)
    except TkgError as exc:
        envelope["error"] = exc.code
        return envelope

    facts = _facts_of(context)
    synthetic = sum(1 for fact in facts if is_synthetic_fact(fact, synthetic_doc_ids))
    envelope["facts"] = len(facts)
    envelope["synthetic_facts"] = synthetic
    envelope["fact_samples"] = [
        {
            "subject": str(fact.get("subject") or "")[:160],
            "predicate": str(fact.get("predicate") or fact.get("label") or "")[:80],
            "object": str(fact.get("object") or "")[:160],
            "synthetic": is_synthetic_fact(fact, synthetic_doc_ids),
        }
        for fact in facts[:20]
    ]
    # The TKG bounds a context bundle (entity and fact caps) and reports the cut
    # as ``limitations``. Keep it: a partial answer must not read as "the graph
    # had nothing more to say".
    limitations = context.get("limitations")
    envelope["limitations"] = limitations if isinstance(limitations, list) else []
    envelope["retrieval_status"] = context.get("retrieval_status")
    envelope["pass"] = passes_for_alert(
        len(facts),
        synthetic=bool(facts) and synthetic == len(facts),
        corroborated=bool(facts) and synthetic < len(facts),
    )
    return envelope


def aggregate(envelopes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Roll per-alert envelopes up into the case-level attribution.

    Split out because a run re-attributes the alerts that were waiting for
    materialisation and has to fold the new envelopes into the same totals.
    """

    rows = list(envelopes)
    passes = {"none": 0, "unconfirmed": 0, "corroborated": 0, "contextualized": 0}
    for envelope in rows:
        passes[envelope.get("pass") or "none"] = passes.get(envelope.get("pass") or "none", 0) + 1

    real_facts = sum(int(envelope.get("facts") or 0) - int(envelope.get("synthetic_facts") or 0) for envelope in rows)
    synthetic_facts = sum(int(envelope.get("synthetic_facts") or 0) for envelope in rows)
    resolved = sum(1 for envelope in rows if envelope.get("entity_id"))
    samples = [sample for envelope in rows for sample in envelope.get("fact_samples") or []]

    return {
        "alerts": rows,
        "passes": passes,
        "resolved": resolved,
        "facts": real_facts + synthetic_facts,
        "real_facts": real_facts,
        "synthetic_facts": synthetic_facts,
        "fact_samples": samples[:80],
        "synthetic_only": bool(synthetic_facts) and real_facts == 0,
        "pending": sum(1 for envelope in rows if str(envelope.get("status") or "") == "pending_materialization"),
    }


async def attribute_alerts(
    client: TkgClient,
    alert_ids: Iterable[str],
    *,
    synthetic_doc_ids: Iterable[str] = (),
    context_limit: int = 40,
    budget_s: float = 20.0,
    on_envelope: Any = None,
) -> dict[str, Any]:
    """Resolve every alert, bounded in concurrency and in wall-clock time.

    ``on_envelope`` is awaited as each alert finishes, which is what makes the
    panel's counters move instead of the whole run appearing at once.
    """

    ids = [str(value) for value in alert_ids]
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def guarded(alert_id: str) -> dict[str, Any]:
        async with semaphore:
            envelope = await _attribute_one(client, alert_id, synthetic_doc_ids=synthetic_doc_ids, context_limit=context_limit)
            if on_envelope is not None:
                await on_envelope(envelope)
            return envelope

    tasks = [asyncio.create_task(guarded(alert_id)) for alert_id in ids]
    envelopes: list[dict[str, Any]] = []
    budget_hit = False
    try:
        async with asyncio.timeout(budget_s):
            envelopes = list(await asyncio.gather(*tasks))
    except TimeoutError:
        budget_hit = True
        envelopes = [task.result() for task in tasks if task.done() and task.exception() is None]
        for task in tasks:
            if not task.done():
                task.cancel()
        done_ids = {envelope["alert_id"] for envelope in envelopes}
        for alert_id in ids:
            if alert_id not in done_ids:
                envelopes.append(
                    {
                        "alert_id": alert_id,
                        "status": "skipped",
                        "entity_id": None,
                        "canonical_key": None,
                        "facts": 0,
                        "synthetic_facts": 0,
                        "pass": "none",
                        "error": R_BUDGET,
                    }
                )

    rolled = aggregate(envelopes)
    rolled["partial"] = budget_hit
    return rolled
