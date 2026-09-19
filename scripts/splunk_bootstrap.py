"""Register a Splunk connector instance against a running AiSOC Core API.

Usage::

    set CORE_API_URL=http://127.0.0.1:8888
    set AISOC_API_TOKEN=<jwt>
    set AISOC_TENANT_ID=<uuid>
    set SPLUNK_BASE_URL=https://splunk.example.com:8089
    set SPLUNK_TOKEN=<token>
    python scripts/splunk_bootstrap.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "splunk"))

from app.bootstrap import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
