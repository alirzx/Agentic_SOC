"""Splunk REST SIEM integration for Agentic SOC (Phase 8.7)."""

from .client import SplunkClient
from .config import SplunkConfig, load_splunk_config
from .models import SplunkSearchInput, SplunkSearchResult
from .tool import run_splunk_search

__all__ = [
    "SplunkClient",
    "SplunkConfig",
    "SplunkSearchInput",
    "SplunkSearchResult",
    "load_splunk_config",
    "run_splunk_search",
]
