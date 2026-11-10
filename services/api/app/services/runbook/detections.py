"""Detect & Fuse activity — how each alert came to exist.

Workflow SOC stage 02 claims that rules and correlation promote noise into
high-signal alerts. That claim had no live surface: the diagram was the only
place it appeared. This module shapes the `alerts` rows the fusion spine already
writes into the evidence an analyst needs to check it per alert:

* which detection rule fired (`rule_id` / `rule_name`, issue #568),
* which connector/OCSF class produced the event,
* how fusion treated it (windowed incident, merged child, or standalone),
* how much duplicate traffic it absorbed (`occurrence_count`).

Everything here is read from persisted columns. Nothing is inferred from the
alert title, and nothing is computed from a table this service does not own — so
the view cannot disagree with the alert it links to.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

FusionState = Literal["incident", "merged", "standalone"]


class DetectionActivityItem(BaseModel):
    """One alert, reduced to the evidence of how it was produced."""

    alert_id: uuid.UUID
    title: str
    severity: str
    created_at: datetime | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    connector_type: str | None = None
    confidence: int | None = None
    occurrence_count: int = 1
    fusion_state: FusionState = "standalone"
    fusion_incident_id: uuid.UUID | None = None
    parent_alert_id: uuid.UUID | None = None

    @property
    def has_rule(self) -> bool:
        return bool((self.rule_name or "").strip() or (self.rule_id or "").strip())


class DetectionActivitySummary(BaseModel):
    """Counts over exactly the rows returned — never over the whole table."""

    examined: int = 0
    distinct_rules: int = 0
    without_rule: int = 0
    merged: int = 0
    incident_linked: int = 0
    deduplicated: int = 0


class DetectionActivityOut(BaseModel):
    summary: DetectionActivitySummary
    items: list[DetectionActivityItem]


def fusion_state_for(
    *,
    fusion_incident_id: uuid.UUID | None,
    is_merged: bool,
    parent_alert_id: uuid.UUID | None,
) -> FusionState:
    """Classify how fusion treated an alert.

    ``incident`` outranks ``merged``: an alert that joined a windowed incident
    was also correlated, and the incident is the more useful fact to show.
    """
    if fusion_incident_id is not None:
        return "incident"
    if is_merged or parent_alert_id is not None:
        return "merged"
    return "standalone"


def item_from_alert(alert: Any) -> DetectionActivityItem:
    """Build one item from an ``Alert`` ORM row (or anything shaped like one)."""
    fusion_incident_id = getattr(alert, "fusion_incident_id", None)
    parent_alert_id = getattr(alert, "parent_alert_id", None)
    is_merged = bool(getattr(alert, "is_merged", False))

    return DetectionActivityItem(
        alert_id=alert.id,
        title=str(getattr(alert, "title", "") or ""),
        severity=str(getattr(alert, "severity", "") or ""),
        created_at=getattr(alert, "created_at", None),
        rule_id=getattr(alert, "rule_id", None),
        rule_name=getattr(alert, "rule_name", None),
        connector_type=getattr(alert, "connector_type", None),
        confidence=getattr(alert, "confidence", None),
        occurrence_count=int(getattr(alert, "occurrence_count", 1) or 1),
        fusion_state=fusion_state_for(
            fusion_incident_id=fusion_incident_id,
            is_merged=is_merged,
            parent_alert_id=parent_alert_id,
        ),
        fusion_incident_id=fusion_incident_id,
        parent_alert_id=parent_alert_id,
    )


def summarize(items: list[DetectionActivityItem]) -> DetectionActivitySummary:
    """Aggregate a page of items. Pure — the caller decides which rows it saw.

    ``distinct_rules`` keys on the rule id when present and falls back to the
    name, so two rules that share a display name still count as two.
    """
    rule_keys = {
        (item.rule_id or item.rule_name or "").strip()
        for item in items
        if item.has_rule
    }

    return DetectionActivitySummary(
        examined=len(items),
        distinct_rules=len(rule_keys),
        without_rule=sum(1 for item in items if not item.has_rule),
        merged=sum(1 for item in items if item.fusion_state == "merged"),
        incident_linked=sum(1 for item in items if item.fusion_state == "incident"),
        deduplicated=sum(1 for item in items if item.occurrence_count > 1),
    )
