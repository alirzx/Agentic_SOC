"""Contract: case investigation report artifacts are proxied through the API.

The Case workspace polls
``GET /cases/{id}/investigations/{run_id}/report.md`` after Investigate with
agent completes. Agents owns the artifact; the API must expose matching
``.md`` / ``.html`` / ``.pdf`` proxy routes so the console does not 404.
"""
from __future__ import annotations

from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "app/api/v1/endpoints/cases.py"


def test_case_investigation_report_proxy_routes_exist() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    for suffix in ("md", "html", "pdf"):
        route = f'/{{case_id}}/investigations/{{run_id}}/report.{suffix}'
        assert route in text, f"missing proxy route for report.{suffix}"
    assert "_proxy_investigation_report" in text
    assert "/api/v1/investigations/{safe_run_id}/report." in text


def test_case_auto_report_markdown_route_still_present() -> None:
    """Auto report (no agent run) must remain available beside the run proxy."""
    text = SOURCE.read_text(encoding="utf-8")
    assert '"/{case_id}/report.md"' in text or "'/{case_id}/report.md'" in text
