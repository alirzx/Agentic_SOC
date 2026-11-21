"""Second-opinion evaluation of an AiSOC case against the Soorin TKG.

Pipeline: load the case's evidence → freeze the payload → rubric precheck →
per-alert attribution (identity/facts, synthetic-aware) → deterministic evidence
floor → optional LLM judge → reconcile → persist. Every stage records a reason
code; a failure downstream never erases the result upstream.
"""

from __future__ import annotations

from app.services.tkg_evaluation.constants import (
    DEFAULT_BUDGET_MS,
    MAX_ALERTS,
    PROFILE,
    R_CACHED,
    R_JUDGE_INVALID,
    R_JUDGE_UNAVAILABLE,
    R_PRECHECK_FAILED,
    R_SYNTHETIC_ONLY,
    R_TKG_NOT_CONFIGURED,
    RUBRIC_VERSION,
)

__all__ = [
    "DEFAULT_BUDGET_MS",
    "MAX_ALERTS",
    "PROFILE",
    "RUBRIC_VERSION",
    "R_CACHED",
    "R_JUDGE_INVALID",
    "R_JUDGE_UNAVAILABLE",
    "R_PRECHECK_FAILED",
    "R_SYNTHETIC_ONLY",
    "R_TKG_NOT_CONFIGURED",
]
