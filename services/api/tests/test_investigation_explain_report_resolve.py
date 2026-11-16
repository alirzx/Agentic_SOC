"""Explain panel must resolve report_hash → readable report_md content."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4


def test_report_hash_matches_artifact_selection():
    """Mirrors the explain_step fallback selection logic."""
    run_id = uuid4()
    focus_id = uuid4()
    report_hash = "abbb0bad1a04ba342d146108ed3e986246f8af8c968c8d3f4679f655db41cbec"
    focus = SimpleNamespace(
        id=focus_id,
        kind="report",
        payload={"duration_ms": 14442, "report_hash": report_hash},
        output_hash=None,
    )
    arts = [
        SimpleNamespace(
            id=uuid4(),
            run_id=run_id,
            event_id=None,
            kind="report_md",
            sha256=report_hash,
            content="# Incident Report\n\nReadable body for analysts.",
            size_bytes=40,
            blob_ref=None,
            created_at=None,
        )
    ]
    seen = {a.id for a in []}
    selected = []
    payload = focus.payload if isinstance(focus.payload, dict) else {}
    want = str(payload.get("report_hash") or "").strip().lower()
    for art in arts:
        if art.id in seen:
            continue
        if want and str(art.sha256 or "").lower() == want:
            selected.append(art)
            seen.add(art.id)
    assert len(selected) == 1
    assert "Readable body" in selected[0].content
