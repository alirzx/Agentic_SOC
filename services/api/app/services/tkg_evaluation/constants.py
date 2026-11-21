"""Constants for the TKG second-opinion evaluation."""

from __future__ import annotations

#: Ingestion profile the Soorin TKG uses for the curated Splunk payload.
PROFILE = "agentic-soc.splunk-curated.v1"

#: Bump when the rubric changes meaning; stored with every run.
RUBRIC_VERSION = "tkg-rubric/1"

#: Verdicts this evaluation may produce. ``benign`` means the TKG evidence
#: supports the alerts being noise; ``insufficient`` means it could not tell.
VERDICTS = ("true_positive", "likely_tp", "needs_more_evidence", "benign", "insufficient")

#: How far the graph got with the alert's identity, weakest to strongest.
PASSES = ("none", "unconfirmed", "corroborated", "contextualized")

#: Score → verdict cut-offs (upper bound exclusive).
SCORE_BANDS = ((85, "true_positive"), (70, "likely_tp"), (50, "needs_more_evidence"), (30, "benign"))

#: A verdict whose facts all trace back to synthetic documents cannot confirm
#: anything: it may at most raise the case to ``needs_more_evidence``.
SYNTHETIC_CONFIDENCE_CAP = 55

#: Corroborating facts needed before an alert counts as ``corroborated``.
CORROBORATION_MIN_FACTS = 2

#: Share of a case's alerts that must exist in the TKG before a verdict is
#: allowed to *confirm* (below it we say ``needs_more_evidence``).
MIN_COVERAGE_FOR_CONFIRM = 0.6

#: The canonical pass was stored before the soft-dedup witnesses were pushed, so
#: a verdict exists even while the graph is still materialising them.
R_CANONICAL_ONLY = "canonical_only_verdict"
#: The operator ended the wait from the panel: scored with alerts still queued.
R_WAIT_SKIPPED = "materialise_wait_skipped"
#: The wait hit ``AISOC_TKG_WAIT_TIMEOUT_S``: scored with alerts still queued.
R_WAIT_TIMEOUT = "materialise_wait_timeout"

#: Payload caps (the TKG accepts 1 MiB per record; stay far below).
#: The graph accepts a 1 MiB record body; the bundle stays below it with margin.
#: A large case (hundreds of soft-dedup witnesses) is compacted first and only
#: refused if even the compact form does not fit.
MAX_ALERTS = 500
MAX_PAYLOAD_CHARS = 700_000
MAX_ALERT_CHARS = 4_000

#: Network budget for one evaluation, and per-call timeout.
DEFAULT_BUDGET_MS = 20_000
DEFAULT_TIMEOUT_S = 20.0

#: Concurrency for per-alert TKG calls (the server rate-limits its LLM, not
#: its read APIs; four concurrent reads stayed well inside it).
CONCURRENCY = 4

#: Reason codes the UI renders. Keep stable: they are persisted.
R_TKG_NOT_CONFIGURED = "tkg_not_configured"
R_TKG_UNREACHABLE = "tkg_unreachable"
R_TKG_AUTH = "tkg_auth_failed"
R_TKG_KB_MISSING = "tkg_kb_missing"
R_PRECHECK_FAILED = "precheck_failed"
R_NO_ALERTS = "no_alerts"
R_NO_PAYLOAD = "no_llm_payload"
R_PAYLOAD_TOO_LARGE = "payload_too_large"
R_TOO_MANY_ALERTS = "too_many_alerts"
R_LOW_COVERAGE = "low_coverage"
R_PARTIAL = "partial_attribution"
R_SYNTHETIC_ONLY = "synthetic_evidence_only"
R_BUDGET = "budget_exhausted"
R_EMPTY_CONTEXT = "no_context_found"
R_CACHED = "served_from_cache"
#: The run was cancelled (or failed) after it had already scored part of the
#: case. The partial verdict is still stored so the work is not lost.
R_RUN_STOPPED_PARTIAL = "run_stopped_partial"
R_TKG_RATE_LIMITED = "tkg_rate_limited"
R_TKG_EXTRACTION_FAILED = "tkg_extraction_failed"
R_JUDGE_UNAVAILABLE = "judge_unavailable"
R_JUDGE_INVALID = "judge_invalid_output"

#: Receipt ``failure_code`` values that mean the graph gave up on the document
#: itself. They are terminal: the extractor already retried a rate limit five
#: times with backoff before writing one of these, so waiting longer cannot make
#: the alert appear. The repair is TKG-side (Library → refresh the document).
#: A receipt whose ``job_status`` is ``failed`` is terminal too, whatever the
#: code: the graph only writes that once no retry is scheduled.
RECEIPT_FAILED_CODES = (
    "soc_document_failed",
    "soc_binding_rejected",
    "soc_identity_conflict",
    "soc_revision_predecessor_failed",
)
