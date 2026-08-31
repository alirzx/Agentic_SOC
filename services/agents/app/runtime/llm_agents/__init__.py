"""LLM-backed tool-using runtime agents (Phase 8.6)."""

from .investigation import run_llm_investigation
from .triage import is_llm_configured, run_llm_triage

__all__ = ["is_llm_configured", "run_llm_triage", "run_llm_investigation"]
