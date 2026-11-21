"""Manual send path: record shape, gating, and dry-run behaviour."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services.tkg_evaluation import sync as sync_module
from app.services.tkg_evaluation.sender import RecordError, build_curated_record

NOTABLE = "005cb761-8591-4280-a8e2-c6fea4e85953"


def _row(**overrides):
    inner = {
        "alert_id": NOTABLE,
        "event_time": "2026-11-16T14:53:52+0330",
        "alert_time": "2026-11-16T16:25:26+0330",
        "rule_name": "ESCU - CertUtil Backup - Rule",
        "rule": {"title": "CertUtil Backup", "description": "x"},
        "alert_fields": {"dest": "win-dc-01.corp.local", "user": "administrator", "network_scope": "corp"},
        "annotations": {"mitre_attack": "T1649"},
    }
    row = {
        "id": "3a77ef5e-0000-4000-8000-000000000001",
        "title": "CertUtil backup",
        "severity": "high",
        "event_time": None,
        "llm_payload": json.dumps({"llm_payload": json.dumps(inner)}),
    }
    row.update(overrides)
    return row


def test_record_uses_payload_notable_id_and_strips_rule_title():
    record, warnings = build_curated_record(_row())
    assert record["notable_id"] == NOTABLE
    assert record["event_time"] == "2026-11-16T14:53:52+0330"
    assert record["alert_time"] == "2026-11-16T16:25:26+0330"
    # ``rule.title`` normalizes onto the same entity as ``rule_name``.
    assert "title" not in record["llm_payload"]["rule"]
    assert "rule_title_omitted_duplicate" in warnings
    assert record["host"] == "win-dc-01.corp.local"
    assert record["user"] == "administrator"
    assert record["network_scope"] == "corp"


def test_record_refuses_alerts_without_notable_or_time():
    with pytest.raises(RecordError) as missing_id:
        build_curated_record(_row(llm_payload=json.dumps({"llm_payload": json.dumps({"event_time": "x"})})))
    assert missing_id.value.code == "missing_alert_id"

    inner = {"alert_id": NOTABLE, "alert_fields": {}}
    with pytest.raises(RecordError) as missing_time:
        build_curated_record(_row(llm_payload=json.dumps({"llm_payload": json.dumps(inner)})))
    assert missing_time.value.code == "event_time_not_iso"


class _FakeClient:
    def __init__(self, *, known: set[str] | None = None) -> None:
        self.known = known or set()
        self.ingested: list[dict] = []
        self.ensured = 0

    async def resolve(self, notable_id: str):
        if notable_id in self.known:
            return {"status": "resolved", "candidates": [{"entity_id": "e1"}]}
        return {"status": "not_found", "candidates": []}

    async def ensure_source(self):
        self.ensured += 1
        return "src-1", "tok"

    async def ingest(self, source_id, token, body):
        self.ingested.append(body)
        return {"receipt_id": f"r{len(self.ingested)}", "job_id": "j", "status": "submitted"}

    async def aclose(self):  # pragma: no cover - only used when client is injected
        return None


def _settings(*, allow_send: bool) -> SimpleNamespace:
    return SimpleNamespace(
        AISOC_TKG_URL="http://tkg.test",
        AISOC_TKG_EMAIL="analyst@test",
        AISOC_TKG_PASSWORD="secret",
        AISOC_TKG_KB_ID="kb-1",
        AISOC_TKG_TENANT="tenant-blue",
        AISOC_TKG_SOURCE_SYSTEM="splunk",
        AISOC_TKG_SOURCE_INSTANCE="splunk-e2e",
        AISOC_TKG_SOURCE_NAME="test-source",
        AISOC_TKG_TIMEOUT_S=5,
        AISOC_TKG_ALLOW_SEND=allow_send,
    )


async def _case_stubs(monkeypatch, rows):
    case_id = uuid4()
    tenant_id = uuid4()

    async def fake_case(db, cid, tid):
        return {"id": case_id, "title": "Case", "severity": "high", "alert_ids": [r["id"] for r in rows]}

    async def fake_alerts(db, tid, cid, ids, excluded):
        return list(rows)

    async def fake_scope(db, cid, tid):
        return [], []

    monkeypatch.setattr(sync_module, "load_case", fake_case)
    monkeypatch.setattr(sync_module, "load_alerts", fake_alerts)
    monkeypatch.setattr(sync_module, "load_case_scope", fake_scope)
    return case_id, tenant_id


def test_dry_run_never_sends(monkeypatch):
    rows = [_row()]
    case_id, tenant_id = asyncio.run(_case_stubs(monkeypatch, rows))
    client = _FakeClient()

    result = asyncio.run(
        sync_module.sync_missing_alerts(
            None,
            tenant_id=tenant_id,
            case_id=case_id,
            dry_run=True,
            client=client,
            settings_obj=_settings(allow_send=True),
        )
    )
    assert result["dry_run"] is True
    assert result["counts"]["would_send"] == 1
    assert client.ingested == []
    assert client.ensured == 0


def test_send_is_blocked_when_the_flag_is_off(monkeypatch):
    rows = [_row()]
    case_id, tenant_id = asyncio.run(_case_stubs(monkeypatch, rows))
    client = _FakeClient()

    result = asyncio.run(
        sync_module.sync_missing_alerts(
            None,
            tenant_id=tenant_id,
            case_id=case_id,
            dry_run=False,
            client=client,
            settings_obj=_settings(allow_send=False),
        )
    )
    assert result["ok"] is False
    assert result["reason"] == "tkg_send_disabled"
    assert client.ingested == []


def test_enabled_send_skips_alerts_already_in_the_graph(monkeypatch):
    rows = [_row()]
    case_id, tenant_id = asyncio.run(_case_stubs(monkeypatch, rows))
    client = _FakeClient(known={NOTABLE})

    result = asyncio.run(
        sync_module.sync_missing_alerts(
            None,
            tenant_id=tenant_id,
            case_id=case_id,
            dry_run=False,
            client=client,
            settings_obj=_settings(allow_send=True),
        )
    )
    assert result["counts"]["sent"] == 0
    assert result["counts"]["already_in_graph"] == 1
    assert client.ingested == []


def test_enabled_send_returns_receipts(monkeypatch):
    rows = [_row()]
    case_id, tenant_id = asyncio.run(_case_stubs(monkeypatch, rows))
    client = _FakeClient()

    result = asyncio.run(
        sync_module.sync_missing_alerts(
            None,
            tenant_id=tenant_id,
            case_id=case_id,
            dry_run=False,
            delay=0,
            client=client,
            settings_obj=_settings(allow_send=True),
        )
    )
    assert result["counts"]["sent"] == 1
    assert result["sent"][0]["receipt_id"] == "r1"
    assert client.ingested[0]["profile"] == "agentic-soc.splunk-curated.v1"
    assert client.ingested[0]["record"]["notable_id"] == NOTABLE
    assert isinstance(datetime.now(UTC), datetime)
