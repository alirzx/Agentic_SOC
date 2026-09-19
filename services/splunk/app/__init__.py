"""Splunk live-ingest operator module (bootstrap + config helpers)."""

from .config import load_bootstrap_config

__all__ = ["load_bootstrap_config"]
