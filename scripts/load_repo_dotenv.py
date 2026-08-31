"""Load monorepo root ``.env`` into ``os.environ`` (canonical for local scripts).

Duplicate keys in the file use **last wins** (matches python-dotenv). Values from
``.env`` override existing process environment so local config is authoritative
when running ``scripts/run_agentic_eval.py`` and ``scripts/test_llm_gateway.py``.
"""

from __future__ import annotations

import os
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def load_repo_dotenv() -> None:
    env_path = _REPO_ROOT / ".env"
    if not env_path.is_file():
        return
    parsed: dict[str, str] = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            parsed[key] = value
    for key, value in parsed.items():
        os.environ[key] = value
