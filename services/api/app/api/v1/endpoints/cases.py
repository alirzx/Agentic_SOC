"""First-class case management (tier2-cases).

Implements the full case lifecycle: new → triaged → investigating → contained →
resolved → closed.  Each case aggregates multiple alerts, maintains an observable
graph, evidence chain, and MITRE ATT&CK coverage map.

Tenant isolation
----------------
Every query in this module is scoped by ``tenant_id = user.tenant_id``. The
``aisoc_cases`` table has carried a ``tenant_id`` column since migration 012
but the API historically did not filter by it, allowing any authenticated
caller to read or mutate another tenant's cases just by guessing a UUID (or
by guessing the short ``INC-001`` form). Companion tables
(``aisoc_case_comments``, ``aisoc_case_tasks``) gained a ``tenant_id``
column in migration 044 and are backfilled from their parent case so the
same RLS predicate applies uniformly.

The ``_resolve_case_id`` helper is also tenant-scoped — looking up
``INC-001`` for tenant A must never return tenant B's INC-001.

Endpoints
---------
* ``GET  /cases``                  List cases (filterable by status/severity/assignee).
* ``POST /cases``                  Create a new case.
* ``GET  /cases/{id}``             Retrieve a case.
* ``PATCH /cases/{id}``            Update case fields (status, severity, assignee, …).
* ``POST /cases/{id}/alerts``      Link alerts to a case.
* ``POST /cases/{id}/observables`` Add / update observable graph nodes/edges.
* ``POST /cases/{id}/comments``    Add a comment / timeline entry.
* ``GET  /cases/{id}/comments``    List comments for a case.
* ``GET  /cases/{id}/evidence``    Export the evidence chain as a structured report.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, bindparam, text

from app.api.v1.deps import AuthUser, CurrentUser, DBSession, require_correlation_writer
from app.core.config import settings
from app.core.logging import safe_log_value
from app.models.case import CaseCandidateDismissal
from app.services.agents_tenant_auth import AgentsTenantAuthError, signed_tenant_headers
from app.services.alert_scope import (
    ScopeError,
    ScopeResult,
    filters_to_raw,
    parse_filters,
    resolve_scope,
)
from app.services.candidate_discovery import CandidateDiscovery, filter_candidates, payload_rule_title
from app.services.case_fanout import (
    FanoutResult,
    fanout_create_case,
    fanout_status_change,
)
from app.services.case_investigation_brief import (
    CaseInvestigationBrief,
    build_case_investigation_brief,
    render_case_report_markdown,
)
from app.services.case_postmortem import build_case_postmortem
from app.services.case_postmortem_html import render_case_postmortem_html
from app.services.case_summary import build_case_summary
from app.services.case_summary_html import render_case_summary_html
from app.services.emitters import emit_case_created_from_correlation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["cases"])

# The agents service owns the actual investigation orchestrator (Pillar-1).
# We keep the route surface on `/cases/{id}/investigate` and
# `/cases/{id}/investigations/{run_id}` for the web console and proxy through
# to the agents service so the front end has a single, stable API origin.
_AGENTS_URL = (os.getenv("AGENTS_SERVICE_URL") or os.getenv("AGENTS_API_URL") or "http://agents:8084").rstrip("/")

# Tight allowlist for proxied request paths. We only ever proxy to a fixed
# upstream (`_AGENTS_URL`) on a known set of investigation routes, so the
# path must be a pure relative path — no scheme, no host, no control bytes,
# no traversal sequences. This neutralises partial-SSRF (an attacker cannot
# redirect the request to a different host) and log-injection (the path
# can never contain CR/LF or other control characters).
_SAFE_PROXY_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./%]*$")


def _validate_agents_path(path: str) -> str:
    """Reject any proxied path that isn't a tightly constrained relative path."""
    if (
        not isinstance(path, str) or not _SAFE_PROXY_PATH_RE.match(path) or ".." in path or path.startswith("//")  # protocol-relative URL
    ):
        raise HTTPException(status_code=400, detail="invalid_request_path")
    return path


# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────

CaseStatus = Literal["new", "triaged", "investigating", "contained", "resolved", "closed"]
CaseSeverity = Literal["info", "low", "medium", "high", "critical"]

# Valid forward-only state transitions
_TRANSITIONS: dict[str, set[str]] = {
    "new": {"triaged"},
    "triaged": {"investigating"},
    "investigating": {"contained", "resolved"},
    "contained": {"resolved"},
    "resolved": {"closed"},
    "closed": set(),
}


class CreateCaseRequest(BaseModel):
    title: str = Field(..., min_length=3)
    description: str | None = None
    severity: CaseSeverity = "medium"
    assignee: str | None = None
    alert_ids: list[uuid.UUID] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    compliance_frameworks: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    sla_due_at: datetime | None = None
    # Workstream 8 — bidirectional ITSM. When the operator selects one or
    # more connector instances at create time, the API fans the new case
    # out to those external systems and persists the linkage in
    # ``case_external_refs``. Connector instances must be tenant-owned,
    # enabled, and declare ``Capability.PUSH_CASE`` (e.g. Jira,
    # ServiceNow). Empty list = case stays AiSOC-only.
    push_to_connector_ids: list[uuid.UUID] = Field(default_factory=list)


class UpdateCaseRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: CaseSeverity | None = None
    status: CaseStatus | None = None
    assignee: str | None = None
    mitre_techniques: list[str] | None = None
    compliance_frameworks: list[str] | None = None
    tags: dict[str, str] | None = None
    sla_due_at: datetime | None = None


class AddAlertsRequest(BaseModel):
    alert_ids: list[uuid.UUID]


class ObservableNode(BaseModel):
    id: str
    kind: Literal["ip", "user", "host", "domain", "hash", "file", "process", "alert"]
    value: str
    tags: list[str] = Field(default_factory=list)


class ObservableEdge(BaseModel):
    source: str
    target: str
    relation: str


class UpdateObservablesRequest(BaseModel):
    nodes: list[ObservableNode] = Field(default_factory=list)
    edges: list[ObservableEdge] = Field(default_factory=list)


class AddCommentRequest(BaseModel):
    body: str = Field(..., min_length=1)
    is_system: bool = False


# ── Correlation-engine contract (v2.0, docs/plans/case/2.0.md §7.2) ──────────


class CorrelationEntityMatch(BaseModel):
    """One shared entity that justified the correlation."""

    kind: Literal["host", "user", "ip", "domain", "hash", "process_guid"]
    value: str = Field(..., min_length=1, max_length=512)


class CorrelationObservation(BaseModel):
    """One atomic attacker action derived by graph-based dedup."""

    observation_id: str = Field(..., min_length=1, max_length=512)
    role: str | None = None
    alert_ids: list[uuid.UUID] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    time_quality: str | None = None


class CreateCaseFromCorrelationRequest(BaseModel):
    """Pre-correlated evidence bundle submitted by the correlation engine.

    ``related_alert_ids`` are **canonical** alerts only. Duplicates collapsed by
    the funnel (``funnel_stage='deduplicated'``) are rejected by the endpoint
    even if a caller includes them — see doc §7.2.
    """

    campaign_key: str = Field(..., min_length=3, max_length=200)
    campaign_theme: str | None = Field(default=None, max_length=80)
    score: int = Field(..., ge=0)
    normalizer_version: str = Field(..., min_length=1, max_length=32)
    related_alert_ids: list[uuid.UUID] = Field(..., min_length=1, max_length=5000)
    title: str | None = Field(default=None, max_length=500)
    description: str | None = None
    severity: CaseSeverity = "medium"
    mitre_techniques: list[str] = Field(default_factory=list)
    entity_matches: list[CorrelationEntityMatch] = Field(default_factory=list)
    observations: list[CorrelationObservation] = Field(default_factory=list)
    correlated_at: datetime | None = None
    source: str = "correlation-engine"



class CaseResponse(BaseModel):
    id: uuid.UUID
    case_number: str | None = None
    title: str
    description: str | None
    severity: str
    status: str
    assignee: str | None
    mitre_techniques: list[str]
    alert_ids: list[uuid.UUID]
    #: Count of alert_ids associated with this case. Computed from len(alert_ids).
    alert_count: int = 0
    rules: dict[str, int] = Field(
        default_factory=dict,
        description="Rule name → count of occurrences in member alerts",
    )
    observable_graph: dict[str, Any]
    evidence_chain: list[dict[str, Any]]
    compliance_frameworks: list[str]
    opened_at: datetime
    triaged_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    created_by: str | None
    #: Which creator produced this case (migration 075). ``graph_correlation``
    #: is the v2.0 correlation engine, ``agentic_funnel`` the legacy promoter,
    #: ``manual`` a human via ``POST /cases``. Both engines run in parallel, so
    #: this is the field operators filter on to tell them apart.
    creation_method: str | None = None
    tags: dict[str, Any]
    sla_due_at: datetime | None
    # Workstream 8 — populated only by ``POST /cases`` (create-time
    # fan-out) and ``PATCH /cases/{id}`` when ``status`` is changed.
    # The list is per-connector-instance and includes failures so the
    # UI can show "Jira ✓ · ServiceNow ✗ (timeout)" beside the case
    # without a follow-up GET. ``None`` (default) means "no fan-out
    # was attempted on this call" and is distinct from ``[]`` ("fan-out
    # was attempted but no connectors were selected").
    fanout_results: list[FanoutResult] | None = None


class CorrelationCaseResponse(CaseResponse):
    """Case plus what the correlation writer actually did with the bundle."""

    created: bool = True
    alerts_linked: int = 0
    alerts_ignored: int = 0
    campaign_key: str | None = None


class CaseListResponse(BaseModel):
    """Paginated cases list with accurate totals (not page-length).

    Older clients expected a bare JSON array. The envelope exposes both
    ``cases`` (web console) and ``items`` (SDK / MCP ``Page`` shape) plus
    ``total`` / ``status_totals`` so the Cases page never shows a fake
    ceiling of 50 when more cases exist.
    """

    cases: list[CaseResponse]
    items: list[CaseResponse]
    total: int
    limit: int
    offset: int
    page: int
    page_size: int
    pages: int
    status_totals: dict[str, int] = Field(default_factory=dict)


class CommentResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    author: str | None
    body: str
    is_system: bool
    created_at: datetime


class EvidenceReport(BaseModel):
    case_id: uuid.UUID
    title: str
    severity: str
    status: str
    alert_count: int
    mitre_techniques: list[str]
    compliance_frameworks: list[str]
    evidence_chain: list[dict[str, Any]]
    generated_at: datetime


# Timeline / tasks
TaskStatus = Literal["todo", "in_progress", "done"]


class TimelineEvent(BaseModel):
    id: str
    type: str  # 'created' | 'status_change' | 'comment' | 'alert_linked' | 'task'
    timestamp: datetime
    title: str
    description: str | None = None
    actor: str | None = None


class TimelineResponse(BaseModel):
    events: list[TimelineEvent]


class GraphNode(BaseModel):
    """Node in the entity graph."""
    id: str = Field(..., description="Entity ID (e.g., IP, hostname, username)")
    label: str = Field(..., description="Display label")
    entity_type: str = Field(..., description="Entity type: ip, host, user, domain, process, etc.")
    severity: str | None = Field(None, description="Related alert severity (high, medium, low)")
    count: int = Field(default=1, description="Number of times this entity appeared")


class GraphEdge(BaseModel):
    """Edge (relationship) in the entity graph."""
    source: str = Field(..., description="Source entity ID")
    target: str = Field(..., description="Target entity ID")
    relationship_type: str = Field(..., description="Type of relationship")
    strength: float = Field(default=1.0, ge=0.0, le=1.0, description="Relationship strength (0.0-1.0)")


class GraphResponse(BaseModel):
    """Entity correlation graph for a case."""
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    total_entities: int = Field(..., description="Total unique entities in case")


class CreateTaskRequest(BaseModel):
    title: str = Field(..., min_length=1)
    status: TaskStatus = "todo"
    assignee: str | None = None
    due_at: datetime | None = Field(None, alias="dueAt")

    model_config = {"populate_by_name": True}


class UpdateTaskRequest(BaseModel):
    title: str | None = None
    status: TaskStatus | None = None
    assignee: str | None = None
    due_at: datetime | None = Field(None, alias="dueAt")

    model_config = {"populate_by_name": True}


class TaskResponse(BaseModel):
    id: str
    title: str
    status: TaskStatus
    assignee: str | None = None
    due_at: datetime | None = Field(None, alias="dueAt")
    created_at: datetime = Field(..., alias="createdAt")

    model_config = {"populate_by_name": True}


def _row_to_task(row: Any) -> TaskResponse:
    return TaskResponse(
        id=str(row.id),
        title=row.title,
        status=row.status,
        assignee=row.assignee,
        dueAt=row.due_at,
        createdAt=row.created_at,
    )


# Investigation proxy schemas (forwarded to the agents service).
class InvestigateRequest(BaseModel):
    alert_summary: str | None = ""


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _coerce_mitre(values: Any) -> list[str]:
    """Normalize mitre_techniques to a list of technique IDs.

    Accepts list[str] or list[dict] like ``{"id": "T1041", "name": "..."}``.
    Older seed fixtures stored objects; newer ones store flat IDs.
    """
    if not values:
        return []
    out: list[str] = []
    for item in values:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            tid = item.get("id") or item.get("technique_id") or item.get("name")
            if tid:
                out.append(str(tid))
    return out


def _coerce_tags(value: Any) -> dict[str, Any]:
    """aisoc_cases.tags is JSONB which may be an object or array."""
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {"labels": [str(v) for v in value]}
    return {}


def _optional_str(value: Any) -> str | None:
    """Return ``value`` only when it is a real string.

    ``_row_to_case`` receives SQLAlchemy rows in production and Mock rows in
    tests; attributing every non-string (NULL, MagicMock, a dict column) to
    ``None`` keeps the response model honest instead of inventing a value.
    """
    return value if isinstance(value, str) else None


async def _get_rule_names(db: DBSession, tenant_id: uuid.UUID, alert_ids: list[Any]) -> dict[str, int]:
    """Retrieve rule_names and their counts from alerts belonging to this case.

    Returns a dict mapping rule_name to count of occurrences in the alerts table,
    filtered by tenant_id for isolation. Returns empty dict if no alerts
    or no rule_names are found. Called by list/detail endpoints to populate
    the case.rules field with rule names and their occurrence counts from case member alerts.
    """
    if not alert_ids:
        return {}

    # Convert alert_ids to UUIDs for safe comparison
    alert_uuids = []
    for aid in alert_ids:
        try:
            if isinstance(aid, str):
                alert_uuids.append(uuid.UUID(aid))
            else:
                alert_uuids.append(aid)
        except (ValueError, TypeError):
            continue

    if not alert_uuids:
        return {}

    q = text("""
        SELECT rule_name, COUNT(*) as count
        FROM alerts
        WHERE tenant_id = :tenant_id
          AND id = ANY(:alert_ids)
          AND rule_name IS NOT NULL
          AND rule_name != ''
        GROUP BY rule_name
        ORDER BY count DESC, rule_name
    """).bindparams(tenant_id=tenant_id, alert_ids=alert_uuids)

    rows = (await db.execute(q)).fetchall()
    return {str(row.rule_name): int(row.count) for row in rows if row.rule_name}


async def _get_rule_names_for_case(
    db: DBSession, tenant_id: uuid.UUID, case_id: uuid.UUID
) -> dict[str, int]:
    """Retrieve rule_names and their counts from ALL alerts (canonical + deduplicated) belonging to this case.

    This differs from _get_rule_names() by querying the actual alerts table WHERE case_id matches,
    rather than using a pre-cached list of alert_ids. This ensures deduplicated alerts are included
    in the rule count.

    Returns a dict mapping rule_name to count of occurrences, sorted by count descending.
    Returns empty dict if no alerts or rule_names are found.
    """
    q = text("""
        SELECT rule_name, COUNT(*) as count
        FROM alerts
        WHERE tenant_id = :tenant_id
          AND case_id = :case_id
          AND rule_name IS NOT NULL
          AND rule_name != ''
        GROUP BY rule_name
        ORDER BY count DESC, rule_name
    """).bindparams(tenant_id=tenant_id, case_id=case_id)

    rows = (await db.execute(q)).fetchall()
    return {str(row.rule_name): int(row.count) for row in rows if row.rule_name}


async def _get_case_techniques(
    db: DBSession, tenant_id: uuid.UUID, case_id: uuid.UUID, alert_ids: list[Any]
) -> list[str]:
    """ATT&CK techniques the case's evidence actually carries, read live.

    ``aisoc_cases.mitre_techniques`` is written once, by the correlation engine,
    from the observations it saw when it opened the case. Alerts are re-assigned,
    re-normalised and soft-deduped afterwards, so that frozen list can name
    techniques no alert in the case carries any more — case ``15b4790b…`` lists
    17 while its 98 evidence alerts carry 12 (``T1027``, ``T1490``, ``T1218.011``,
    ``T1204.002`` and ``T1021.001`` appear on no alert of the case). Rebuild it
    from the alerts themselves: the canonical members plus the soft-dedup
    witnesses whose winner is a member, which is exactly the set the correlation
    graph scores.
    """

    winners = sorted({str(value) for value in (alert_ids or [])})
    rows = (
        await db.execute(
            text(
                """
                SELECT DISTINCT tech.value AS technique
                FROM alerts a
                CROSS JOIN LATERAL jsonb_array_elements_text(
                    CASE WHEN jsonb_typeof(a.mitre_techniques) = 'array'
                         THEN a.mitre_techniques
                         ELSE '[]'::jsonb
                    END
                ) AS tech(value)
                LEFT JOIN unnest(CAST(:winners AS text[])) AS w(winner) ON TRUE
                WHERE a.tenant_id = :tenant_id
                  AND (
                    a.case_id = :case_id
                    OR (
                        a.funnel_stage = 'deduplicated'
                        AND a.tags @> to_jsonb(ARRAY['deduplicated_into:' || w.winner])
                    )
                  )
                ORDER BY technique
                """
            ).bindparams(
                tenant_id=tenant_id,
                case_id=case_id,
                winners=winners or [""],
            )
        )
    ).fetchall()
    return [str(row.technique) for row in rows if row.technique]


async def _get_rule_alert_ids(
    db: DBSession, tenant_id: uuid.UUID, alert_ids: list[str]
) -> dict[str, list[str]]:
    """Rule name → the alert ids that carry it, over any alert set.

    ``_get_rule_names``/``_get_rule_names_for_case`` count only what the alerts
    table says belongs to a case, which for a correlated campaign is the
    *canonical* member set (9 alerts on a campaign of 98) — so every rule showed
    ``1`` while the Alerts tab listed dozens of rows. This helper answers the
    question the Rules tab actually asks: which evidence alerts carry the rule.

    Called with the pre-scope available ids, so a rule the analyst excluded can
    still be listed (and restored) even though it is not in the kept set.
    """

    if not alert_ids:
        return {}
    rows = (
        await db.execute(
            text("""
                SELECT rule_name, ARRAY_AGG(id::text) AS ids
                FROM alerts
                WHERE tenant_id = :tenant_id
                  AND id::text = ANY(:ids)
                  AND rule_name IS NOT NULL
                  AND rule_name != ''
                GROUP BY rule_name
            """).bindparams(tenant_id=tenant_id, ids=list(alert_ids))
        )
    ).fetchall()
    return {str(row.rule_name): list(row.ids or []) for row in rows if row.rule_name}


def _row_to_case(row: Any) -> CaseResponse:
    return CaseResponse(
        id=row.id,
        case_number=getattr(row, "case_number", None),
        title=row.title,
        description=row.description,
        severity=row.severity,
        status=row.status,
        assignee=row.assignee,
        mitre_techniques=_coerce_mitre(row.mitre_techniques),
        alert_ids=list(row.alert_ids or []),
        alert_count=len(row.alert_ids or []),
        observable_graph=dict(row.observable_graph or {}),
        evidence_chain=list(row.evidence_chain or []),
        compliance_frameworks=list(row.compliance_frameworks or []),
        opened_at=row.opened_at,
        triaged_at=row.triaged_at,
        resolved_at=row.resolved_at,
        closed_at=row.closed_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        created_by=row.created_by,    # ``getattr`` keeps the API readable on an install that has not run
    # migration 075 yet (same defensive pattern as ``case_number``).
    creation_method=_optional_str(getattr(row, "creation_method", None)),
        tags=_coerce_tags(row.tags),
        sla_due_at=row.sla_due_at,
        # Distinct rule_name values from alerts in this case (rule_name → count).
        # Populated by the list/detail endpoints; empty means "not computed / no resolvable alerts".
        rules={},
    )


def partition_correlation_alerts(rows: list[Any]) -> tuple[list[Any], int]:
    """Split correlated alerts into case-eligible rows and an ignored count.

    Doc §7.2: alerts the funnel collapsed to ``funnel_stage='deduplicated'`` are
    never case members. They remain evidence in the correlation observations but
    the case narrative is built from canonical alerts only. Extracted as a pure
    helper so the rule is unit-testable without a database session.
    """
    eligible = [row for row in rows if str(row.funnel_stage or "") != "deduplicated"]
    return eligible, len(rows) - len(eligible)


def partition_claimable_alerts(
    rows: list[Any], *, target_case_id: uuid.UUID | None
) -> tuple[list[Any], int]:
    """Split eligible alerts into the ones this write can actually claim.

    The claim ``UPDATE`` only accepts ``case_id IS NULL`` or the case being
    written, so an alert owned by a *different* case can never become a member.
    Listing it anyway made a case claim evidence it did not own: the workspace
    showed four linked alerts while the investigation brief, which reads
    ``alerts.case_id``, correctly showed zero.

    Pure helper so the rule is unit-testable without a database session.
    """
    claimable = [
        row
        for row in rows
        if row.case_id is None
        or (target_case_id is not None and row.case_id == target_case_id)
    ]
    return claimable, len(rows) - len(claimable)


async def _resolve_case_id(case_id: str, db: Any, tenant_id: uuid.UUID) -> uuid.UUID:
    """Resolve a case identifier (UUID **or** human-readable case_number) to a UUID
    scoped to the caller's tenant.

    The web console and demo deeplinks use short identifiers like ``INC-001``,
    while the database primary key is a UUID. Accepting both forms here keeps
    the API ergonomic without forcing the front end to do a separate lookup.

    Tenant scoping is enforced in both branches:

    * For the UUID branch we return the parsed UUID without touching the DB;
      callers must still apply ``WHERE tenant_id = :tenant_id`` in their own
      query, which they all do. (We don't probe existence here because every
      caller does its own SELECT and would issue a redundant round-trip.)
    * For the ``case_number`` branch we look up the row with
      ``WHERE tenant_id = :tenant_id AND case_number = :case_number`` so an
      attacker can't enumerate another tenant's INC-NNN identifiers.

    Raises ``404`` if the identifier doesn't match either form within the
    caller's tenant.
    """
    case_id = (case_id or "").strip()
    if not case_id:
        raise HTTPException(status_code=404, detail="Case not found.")

    # Try UUID first — that's the canonical form. Tenant scoping is enforced
    # by the per-endpoint queries that consume the returned UUID, so we
    # don't need a DB round-trip just to validate the format.
    try:
        return uuid.UUID(case_id)
    except (ValueError, AttributeError):
        pass

    # Fall back to case_number lookup. Use a parameterized query — never
    # interpolate the raw string into SQL — and scope by tenant so the
    # short-id form can't be used as a cross-tenant oracle.
    row = (
        await db.execute(
            text(
                "SELECT id FROM aisoc_cases WHERE tenant_id = :tenant_id AND case_number = :case_number ORDER BY created_at DESC LIMIT 1"
            ).bindparams(tenant_id=tenant_id, case_number=case_id)
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")
    return row.id


# ────────────────────────────────────────────────────────────────────────────
# Candidates Discovery Endpoints (Correlation Engine v2.0)
# ────────────────────────────────────────────────────────────────────────────


class CandidateTriage(BaseModel):
    """Auto-triage verdict distribution across a candidate's member alerts.

    Display/filter metadata only. The correlation engine excludes auto-closed
    ``false_positive`` / ``benign`` / ``benign_true_positive`` alerts before it
    forms components, but the surviving verdicts never influenced L1/L2/L3 — so
    they are reported here rather than folded into ``score``.
    """

    verdicts: dict[str, int] = Field(
        default_factory=dict, description="Verdict → number of member alerts"
    )
    true_positive: int = 0
    likely_tp: int = 0
    needs_review: int = 0
    escalate: int = 0
    unreviewed: int = Field(0, description="Alerts triage has not classified yet")
    reviewed: int = 0
    max_confidence: int | None = Field(
        None, description="Highest triage confidence among members (0–100), when known"
    )
    avg_confidence: int | None = Field(
        None, description="Mean triage confidence among members (0–100), when known"
    )


class CandidateCard(BaseModel):
    """Lightweight summary card for candidate in list view"""
    candidate_key: str = Field(..., description="Unique component identifier")
    campaign_theme: str = Field(..., description="Human theme: LSASS_CREDENTIAL_ACCESS, SMB_LATERAL_MOVEMENT, etc.")
    score: int = Field(
        ...,
        ge=0,
        description=(
            "Peak pair score: L1+L2+L3 of the strongest single link that joined "
            "the observations (the number θ gates). This is what min_score filters on. "
            "The list endpoint only ever returns components at or above θ (>= 1); "
            "0 is reserved for a *case* whose evidence no longer scores — the "
            "inspect view must render that honestly instead of failing."
        ),
    )
    evidence_score: int = Field(
        0,
        ge=0,
        description=(
            "Sum of L1+L2+L3 over every scored pair. Grows with candidate size; "
            "use it for triage depth, never as a quality score."
        ),
    )
    pair_count: int = Field(0, ge=0, description="Pairs with a non-zero score")
    alert_count: int = Field(..., ge=1)
    entity_summary: dict[str, int] = Field(..., description="Entity kind → count")
    time_first: datetime
    time_last: datetime
    severity: str | None = None
    triage: CandidateTriage = Field(
        default_factory=CandidateTriage,
        description="Auto-triage verdict distribution of the member alerts",
    )
    rules: dict[str, int] = Field(
        default_factory=dict,
        description="Rule name → count of occurrences in member alerts",
    )


@router.get("/candidates", response_model=list[CandidateCard], summary="List correlation candidates")
async def list_candidates(
    db: DBSession,
    user: AuthUser,
    q: str | None = Query(
        None,
        max_length=200,
        description="Free text: candidate key, theme, entity value, MITRE technique or alert id",
    ),
    min_score: int = Query(
        3,
        ge=1,
        description=(
            "Minimum **peak pair score** (θ=3 is the merge threshold). "
            "Filters the list only — it never changes how components are formed."
        ),
    ),
    severity: str | None = Query(None, description="Filter: info|low|medium|high|critical"),
    entity_kind: str | None = Query(
        None,
        description=(
            "Comma-separated entity buckets that must all be present: "
            "hosts,users,ips,domains,techniques"
        ),
    ),
    triage: str | None = Query(
        None,
        description=(
            "Comma-separated auto-triage verdicts; keeps candidates that contain "
            "**any** of them: true_positive, likely_tp, needs_review, escalate, unreviewed"
        ),
    ),
    min_alerts: int | None = Query(None, ge=1, le=100_000, description="Minimum member alerts"),
    max_alerts: int | None = Query(None, ge=1, le=100_000, description="Maximum member alerts"),
    since: datetime | None = Query(None, description="Keep candidates whose span overlaps this start"),
    until: datetime | None = Query(None, description="Keep candidates whose span overlaps this end"),
    sort: str = Query("score", pattern="^(score|recent|alerts)$", description="score|recent|alerts"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[CandidateCard]:
    """
    List correlation engine candidates (connected components) not yet in cases.

    **Tenant-scoped:** Returns only candidates for user's tenant.

    **Filtering** (all optional, applied after discovery):
    - `q`: free-text over entity values, techniques, theme, candidate key
    - `min_score`: minimum **peak pair score** — the strongest single link
    - `severity`: maximum alert severity in the component
    - `entity_kind`: require host/user/IP/domain/technique evidence
    - `triage`: require a member alert with one of the named auto-triage verdicts
    - `min_alerts` / `max_alerts`: component size
    - `since` / `until`: event-time overlap with the window
    - `sort`: `score` (default), `recent`, `alerts`

    **Note:** The merge threshold θ is fixed (3). `min_score` filters the list;
    it deliberately does **not** re-run discovery with a higher threshold, which
    used to silently split candidates when an analyst moved the slider.

    **Response:** `CandidateCard` objects with the peak pair score, the evidence
    total, entity summary, event-time span and severity.
    """

    tenant_id = user.tenant_id
    discovery = CandidateDiscovery(
        db,
        lookback_hours=getattr(settings, "correlation_lookback_hours", 72),
    )

    # Get all candidates
    all_candidates = await discovery.run(str(tenant_id))

    # Filter out dismissed candidates (dismissed_at > 24h ago)
    from sqlalchemy import and_, select
    stmt = select(CaseCandidateDismissal.candidate_key).where(
        and_(
            CaseCandidateDismissal.tenant_id == tenant_id,
            CaseCandidateDismissal.dismissed_at > datetime.now(UTC) - timedelta(hours=24),
        )
    )
    dismissed_result = await db.execute(stmt)
    dismissed_keys = {row[0] for row in dismissed_result.all()}
    all_candidates = [c for c in all_candidates if c["candidate_key"] not in dismissed_keys]

    entity_kinds = [
        kind.strip() for kind in (entity_kind or "").split(",") if kind.strip()
    ]
    triage_buckets = [
        value.strip() for value in (triage or "").split(",") if value.strip()
    ]
    all_candidates = filter_candidates(
        all_candidates,
        q=q,
        min_score=min_score,
        severity=severity,
        entity_kinds=entity_kinds,
        triage=triage_buckets,
        min_alerts=min_alerts,
        max_alerts=max_alerts,
        since=since,
        until=until,
        sort=sort,
    )

    # Apply pagination
    paginated = all_candidates[offset : offset + limit]

    # Build response with rules extracted from alert_ids
    result = []
    for c in paginated:
        alert_ids = c.get("alert_ids", [])
        rules = await _get_rule_names(db, tenant_id, alert_ids) if alert_ids else {}
        result.append(
            CandidateCard(
                candidate_key=c["candidate_key"],
                campaign_theme=c["campaign_theme"],
                score=c["score"],
                evidence_score=int(c.get("evidence_score") or 0),
                pair_count=int(c.get("pair_count") or 0),
                alert_count=c["alert_count"],
                entity_summary={
                    "hosts": len(c.get("entities", {}).get("hosts", [])),
                    "users": len(c.get("entities", {}).get("users", [])),
                    "ips": len(c.get("entities", {}).get("ips", [])),
                    "domains": len(c.get("entities", {}).get("domains", [])),
                    "techniques": len(c.get("techniques", [])),
                },
                time_first=c["time_first"],
                time_last=c["time_last"],
                severity=c.get("severity"),
                triage=CandidateTriage(**(c.get("triage") or {})),
                rules=rules,
            )
        )
    return result


class CandidateMatchedValue(BaseModel):
    """A single value two observations share (why a pair was joined).

    ``weight`` is the engine's key weight (3 strong / 2 medium / 1 weak) — the
    amount this value contributed to L1, so the number can be checked by hand.
    """
    kind: str
    value: str
    weight: int = 1


class CandidateObservationToken(BaseModel):
    """One correlation key an observation contributed, with its L1 weight.

    ``value`` is the raw value (``mswin-dc01``, ``md5=…``); ``token`` is the
    engine's full ``kind:value`` string (host-scoped GUIDs are
    ``process_guid:<scope>|<guid>``). ``estimated`` marks rows written before
    migration 080, where the weight is the per-kind default rather than the one
    the engine actually scored with.
    """
    token: str
    kind: str
    value: str
    weight: int = 1
    estimated: bool = False


class CandidateObservation(BaseModel):
    """One atomic attacker action (graph-based dedup output)."""
    observation_key: str
    role: str | None = None
    techniques: list[str] = Field(default_factory=list)
    #: Analytic stories the observation's alerts belong to (engine L2 input).
    stories: list[str] = Field(default_factory=list)
    #: Splunk/Lockheed kill-chain phases (engine L2 input, shown in the footer).
    kill_chain: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    alert_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    time_quality: str | None = None
    #: The keys this observation contributed to scoring, strongest first.
    tokens: list[CandidateObservationToken] = Field(default_factory=list)


class CandidatePairScore(BaseModel):
    """L1/L2/L3 breakdown for a pair of observations."""
    source: str
    target: str
    l1: int = 0
    l2: int = 0
    l3: int = 0
    score: int = 0
    matched: list[CandidateMatchedValue] = Field(default_factory=list)
    l3_via: CandidateL3Explanation | None = None
    threshold_met: bool = False


class CandidateL3Explanation(BaseModel):
    """Why a pair earned the L3 graph-proximity point.

    ``via`` is the third observation both sides reach; ``left_token`` and
    ``right_token`` are the two distinct keys that make the path real.
    """

    via: str
    left_token: str
    right_token: str


class CandidateTimelineEvent(BaseModel):
    """A member alert placed on the candidate timeline."""
    alert_id: str
    observation_key: str | None = None
    title: str | None = None
    #: From ``alerts.llm_payload.rule.title`` — the analytic name, when it adds
    #: information beyond ``title`` (which mirrors the Splunk ``search_name``).
    payload_title: str | None = None
    severity: str | None = None
    time: datetime | None = None
    techniques: list[str] = Field(default_factory=list)
    #: Product-funnel stage of the alert. ``deduplicated`` means it is soft-dedup
    #: evidence: still a case witness and still scored, but hidden from the
    #: alerts workbench — so the inspect view labels it instead of pretending
    #: it is an ordinary visible alert.
    funnel_stage: str | None = None
    deduplicated: bool = False
    #: How many raw events this alert stands for (set by exact dedupe).
    occurrence_count: int | None = None


class CandidateGraphNode(BaseModel):
    id: str
    kind: str = Field(
        ..., description="observation | host | user | ip | domain | hash | process_guid | key"
    )
    label: str
    #: Full `kind:value` key for entity/key nodes — the label is truncated.
    token: str | None = None
    alert_count: int = 0
    techniques: list[str] = Field(default_factory=list)
    #: Kill-chain phases for an observation node (empty for entity nodes).
    kill_chain: list[str] = Field(default_factory=list)
    observation_key: str | None = None


class CandidateGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    kind: str = Field(
        ...,
        description=(
            "CORRELATION | OBSERVED_ON | INVOLVES_USER | USES_IP | QUERIED_DOMAIN | "
            "MATCHES_HASH | INVOKES_PROCESS | CONTRIBUTES_KEY"
        ),
    )
    #: Pair score for CORRELATION edges; key weight for key edges.
    weight: int = 1
    threshold_met: bool = True
    matched: list[CandidateMatchedValue] = Field(default_factory=list)
    l3_via: CandidateL3Explanation | None = None
    #: Full `kind:value` key this edge connects, on key (non-CORRELATION) edges.
    token: str | None = None
    #: ATT&CK role the observation(s) carry, on OBSERVATION (role) edges.
    role: str | None = None
    #: Every role collapsed onto this entity pair (dominant one is `role`).
    roles: list[str] = Field(default_factory=list)
    #: Observation keys this edge represents.
    observations: list[str] = Field(default_factory=list)
    #: How many observations were folded together onto this entity pair.
    count: int = 1
    #: Alerts behind those observations.
    alert_count: int = 0
    #: Endpoints of the widest contributing observation (tree-projected > 4).
    endpoint_count: int = 0


class CandidateGraph(BaseModel):
    nodes: list[CandidateGraphNode] = Field(default_factory=list)
    edges: list[CandidateGraphEdge] = Field(default_factory=list)
    theta: int = 3
    #: Which projection this payload carries: `node` (observation hubs, the
    #: historical shape) or `edge` (observations drawn as role edges).
    observation_mode: str = "node"


class CandidateScoreBreakdown(BaseModel):
    """How the component score adds up across every scoring layer."""
    l1: int = 0
    l2: int = 0
    l3: int = 0
    theta: int = 3
    peak_score: int = 0
    component_score: int = 0


class ScopeDrop(BaseModel):
    """One alert the analyst's scope removed from the analysis."""
    alert_id: str
    title: str | None = None
    reason: str


class CandidateScopeEcho(BaseModel):
    """What was excluded, why, and from how much evidence.

    Echoed back so the modal can show "3 of 18 alerts excluded" with an undo
    path instead of silently rendering a thinner graph.
    """
    excluded_alert_ids: list[str] = Field(default_factory=list)
    #: Raw ``field|op|value|mode`` strings as the client sent them.
    filters: list[str] = Field(default_factory=list)
    dropped: list[ScopeDrop] = Field(default_factory=list)
    available_alert_count: int = 0


class CandidateDetail(CandidateCard):
    """Full candidate with all entities, techniques and the correlation graph"""
    alert_ids: list[str] = Field(..., description="All member alert IDs")
    #: Canonical members of the case (``aisoc_cases.alert_ids``). ``alert_count``
    #: is the wider evidence set and also counts soft-dedup losers, so the two
    #: numbers differ by exactly the duplicate evidence a case carries.
    member_alert_count: int = 0
    entities: dict[str, list[str]] = Field(..., description="Grouped entities by kind")
    techniques: list[str] = Field(default_factory=list, description="MITRE techniques observed")
    # Inspect-view payload. Every field below is derived from the same scored
    # pair set that formed this component, so the analyst sees the real reason
    # the engine grouped these alerts instead of a bare score.
    observations: list[CandidateObservation] = Field(
        default_factory=list, description="Atomic attacker actions in this candidate"
    )
    pair_scores: list[CandidatePairScore] = Field(
        default_factory=list, description="L1/L2/L3 per observation pair, strongest first"
    )
    timeline: list[CandidateTimelineEvent] = Field(
        default_factory=list, description="Member alerts in chronological order"
    )
    graph: CandidateGraph | None = Field(
        default=None, description="Nodes/edges ready for graph rendering"
    )
    score_breakdown: CandidateScoreBreakdown | None = Field(
        default=None, description="Where the component score comes from"
    )
    scope: CandidateScopeEcho | None = Field(
        default=None,
        description="Alerts excluded from this view (and why), when a scope was applied",
    )
    rule_alert_ids: dict[str, list[str]] = Field(
        default_factory=dict,
        description=(
            "Rule name → evidence alert ids, resolved before the scope so a rule "
            "the analyst excluded can still be listed and restored"
        ),
    )


class CandidateScopeRequest(BaseModel):
    """Scope applied to a candidate when it is promoted into a case.

    Same shape the inspect view accepts, so "exclude these and create the case"
    is one round trip rather than a client-side subtraction the server cannot
    verify.
    """
    excluded_alert_ids: list[str] = Field(default_factory=list)
    filters: list[str] = Field(
        default_factory=list,
        description="llm_payload scope filters: field|op|value|mode",
    )


def _parse_scope_request(
    exclude: str | None, filters: list[str] | None
) -> tuple[list[str], list[str]]:
    """Validate the scope query parameters, 422 on anything uninterpretable."""

    excluded_ids = [part.strip() for part in (exclude or "").split(",") if part.strip()]
    try:
        parsed = parse_filters(filters)
    except ScopeError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_scope_filter", "reason": str(exc)},
        ) from exc
    return excluded_ids, filters_to_raw(parsed)


def _empty_component(candidate: dict[str, Any], kept_ids: list[str]) -> dict[str, Any]:
    """A candidate whose scope removed every alert.

    Deliberately not ``None``: the modal has to render "nothing survives this
    scope" with the alert list intact enough to undo, not a 404 for a candidate
    that still exists.
    """

    now = datetime.now(UTC)
    return {
        **{k: candidate.get(k) for k in ("candidate_key", "campaign_theme")},
        "score": 0,
        "evidence_score": 0,
        "pair_count": 0,
        "alert_count": len(kept_ids),
        "alert_ids": list(kept_ids),
        "entities": {},
        "techniques": [],
        "time_first": now,
        "time_last": now,
        "severity": candidate.get("severity"),
        "triage": {},
        "observations": [],
        "pair_scores": [],
        "timeline": [],
        "graph": {
            "nodes": [],
            "edges": [],
            "theta": (candidate.get("score_breakdown") or {}).get("theta", 3),
        },
        "score_breakdown": {
            "l1": 0,
            "l2": 0,
            "l3": 0,
            "theta": (candidate.get("score_breakdown") or {}).get("theta", 3),
            "peak_score": 0,
            "component_score": 0,
        },
    }


#: Accepted values for the graph projection request parameter.
_OBSERVATION_MODES: tuple[str, ...] = ("node", "edge")


def _observation_mode(requested: str | None) -> str:
    """Resolve the graph projection: explicit request → env default → ``node``.

    ``AISOC_CORRELATION_GRAPH_EDGES=1`` flips the default once the edge
    projection has been reviewed; the per-request ``?observations=node|edge``
    override exists so a single case can be compared without a redeploy.
    """

    if requested in _OBSERVATION_MODES:
        return str(requested)
    flag = (os.getenv("AISOC_CORRELATION_GRAPH_EDGES", "0") or "").strip().lower()
    return "edge" if flag in {"1", "true", "yes", "on"} else "node"


async def _apply_scope(
    discovery: CandidateDiscovery,
    tenant_id: Any,
    candidate: dict[str, Any],
    scoped: ScopeResult,
    *,
    observation_mode: str = "node",
) -> dict[str, Any]:
    """Re-describe the component for the alerts the scope kept.

    The component key is preserved: it is what the analyst opened and what the
    browser is polling; only the evidence underneath it changed. Everything else
    (score, graph, timeline, techniques) is recomputed from the surviving
    observations, so the numbers shown are the numbers the reduced evidence set
    actually scores.
    """

    payload = await discovery.describe_alert_set(
        tenant_id, scoped.kept_ids, observation_mode=observation_mode
    )
    if payload is None:
        return _empty_component(candidate, scoped.kept_ids)

    merged = {**candidate, **payload}
    for name in ("candidate_key", "campaign_theme"):
        merged[name] = candidate.get(name)
    return merged


def _detail_model(
    candidate: dict[str, Any],
    *,
    candidate_key: str,
    campaign_theme: str,
    scope: CandidateScopeEcho | None = None,
) -> CandidateDetail:
    """Build the API model every correlation view renders (candidate or case)."""

    entities = candidate.get("entities") or {}
    return CandidateDetail(
        candidate_key=candidate_key,
        campaign_theme=campaign_theme,
        score=int(candidate.get("score") or 0),
        evidence_score=int(candidate.get("evidence_score") or 0),
        pair_count=int(candidate.get("pair_count") or 0),
        alert_count=int(candidate.get("alert_count") or 0),
        member_alert_count=int(candidate.get("member_alert_count") or 0),
        alert_ids=[str(alert_id) for alert_id in candidate.get("alert_ids", [])],
        entities={
            kind: [str(entity) for entity in values] for kind, values in entities.items()
        },
        techniques=[str(technique) for technique in candidate.get("techniques", [])],
        observations=candidate.get("observations", []),
        pair_scores=candidate.get("pair_scores", []),
        timeline=candidate.get("timeline", []),
        graph=candidate.get("graph"),
        score_breakdown=candidate.get("score_breakdown"),
        entity_summary={
            "hosts": len(entities.get("hosts", [])),
            "users": len(entities.get("users", [])),
            "ips": len(entities.get("ips", [])),
            "domains": len(entities.get("domains", [])),
            "techniques": len(candidate.get("techniques", [])),
        },
        time_first=candidate.get("time_first") or datetime.now(UTC),
        time_last=candidate.get("time_last") or datetime.now(UTC),
        severity=candidate.get("severity"),
        triage=CandidateTriage(**(candidate.get("triage") or {})),
        rules=candidate.get("rules") or {},
        rule_alert_ids=candidate.get("rule_alert_ids") or {},
        scope=scope,
    )


@router.get(
    "/candidates/{candidate_key}",
    response_model=CandidateDetail,
    summary="Get candidate details",
)
async def get_candidate_detail(
    candidate_key: str,
    db: DBSession,
    user: AuthUser,
    exclude: str | None = Query(
        None,
        description="Comma-separated member alert ids the analyst excluded from this view",
    ),
    flt: list[str] | None = Query(
        None,
        description=(
            "Repeatable alert-scope filter over llm_payload: "
            "'llm_payload.<path>|op|value|include|exclude'"
        ),
    ),
    observations: str | None = Query(
        None,
        description=(
            "Graph projection for observations: 'node' (hub nodes, default) or "
            "'edge' (each observation drawn as a role edge between its entities)"
        ),
    ),
) -> CandidateDetail:
    """Full inspect payload for one candidate, optionally narrowed by a scope.

    **Scope** (``exclude``, ``flt``) recomputes the component from the alerts
    that survive it — the graph, the pair scores and the timeline all describe
    the reduced evidence, never the full set with items hidden client-side.

    **Response includes:** member alerts, grouped entities, MITRE techniques,
    the L1/L2/L3 breakdown per pair, the render-ready graph and the timeline.
    """

    tenant_id = user.tenant_id
    excluded_ids, scope_filters = _parse_scope_request(exclude, flt)
    discovery = CandidateDiscovery(
        db,
        lookback_hours=getattr(settings, "correlation_lookback_hours", 72),
    )

    graph_mode = _observation_mode(observations)

    # `include_graph` adds the observations/pair-scores/graph/timeline payload
    # that only the inspect view needs — the list endpoint never pays for it.
    all_candidates = await discovery.run(
        str(tenant_id), include_graph=True, observation_mode=graph_mode
    )
    candidate = next((c for c in all_candidates if c["candidate_key"] == candidate_key), None)
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    scope_echo: CandidateScopeEcho | None = None
    if excluded_ids or scope_filters:
        try:
            parsed = parse_filters(scope_filters)
        except ScopeError as exc:  # already validated above; defence in depth
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        scoped = await resolve_scope(
            db,
            tenant_id,
            candidate.get("alert_ids", []),
            excluded_ids=excluded_ids,
            filters=parsed,
        )
        candidate = await _apply_scope(
            discovery, tenant_id, candidate, scoped, observation_mode=graph_mode
        )
        scope_echo = CandidateScopeEcho(
            excluded_alert_ids=excluded_ids,
            filters=scope_filters,
            dropped=[
                ScopeDrop(
                    alert_id=str(item["alert_id"]),
                    title=item.get("title"),
                    reason=str(item.get("reason") or "excluded"),
                )
                for item in scoped.dropped
            ],
            available_alert_count=len(scoped.known_ids),
        )

    # Extract rules from the candidate's alert IDs
    alert_ids = candidate.get("alert_ids", [])
    rules = await _get_rule_names(db, user.tenant_id, alert_ids)
    candidate["rules"] = rules

    return _detail_model(
        candidate,
        candidate_key=candidate_key,
        campaign_theme=str(candidate.get("campaign_theme") or "CORRELATED_ALERTS"),
        scope=scope_echo,
    )

    # Get all candidates and find matching one. `include_graph` adds the
    # observations/pair-scores/graph/timeline payload that only the inspect
    # view needs — the list endpoint never pays for it.
    all_candidates = await discovery.run(str(tenant_id), include_graph=True)
    candidate = next((c for c in all_candidates if c["candidate_key"] == candidate_key), None)

    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    normalized_alert_ids = [str(alert_id) for alert_id in candidate.get("alert_ids", [])]
    normalized_entities = {
        kind: [str(entity) for entity in values]
        for kind, values in (candidate.get("entities", {}) or {}).items()
    }

    return CandidateDetail(
        candidate_key=candidate["candidate_key"],
        campaign_theme=candidate["campaign_theme"],
        score=candidate["score"],
        evidence_score=int(candidate.get("evidence_score") or 0),
        pair_count=int(candidate.get("pair_count") or 0),
        alert_count=candidate["alert_count"],
        alert_ids=normalized_alert_ids,
        entities=normalized_entities,
        techniques=[str(technique) for technique in candidate.get("techniques", [])],
        observations=candidate.get("observations", []),
        pair_scores=candidate.get("pair_scores", []),
        timeline=candidate.get("timeline", []),
        graph=candidate.get("graph"),
        score_breakdown=candidate.get("score_breakdown"),
        entity_summary={
            "hosts": len(candidate.get("entities", {}).get("hosts", [])),
            "users": len(candidate.get("entities", {}).get("users", [])),
            "ips": len(candidate.get("entities", {}).get("ips", [])),
            "domains": len(candidate.get("entities", {}).get("domains", [])),
            "techniques": len(candidate.get("techniques", [])),
        },
        time_first=candidate["time_first"],
        time_last=candidate["time_last"],
        severity=candidate.get("severity"),
        triage=CandidateTriage(**(candidate.get("triage") or {})),
    )


def candidate_observations(candidate: dict[str, Any]) -> list[CorrelationObservation]:
    """Map a discovered candidate's observations onto the correlation contract.

    The candidate's observations are the evidence that produced its score, so they
    travel with the bundle. Without them the case description, its tags and the
    correlation timeline all read ``observations: 0`` even for a 55-alert campaign
    with 91 scored pairs.

    Rows without a key, or with an alert id that is not a UUID, are skipped rather
    than aborting the whole promotion: the case is still valid evidence.
    """
    observations: list[CorrelationObservation] = []
    for observation in candidate.get("observations") or []:
        if not isinstance(observation, dict):
            continue
        observation_key = str(observation.get("observation_key") or "").strip()
        if not observation_key:
            continue
        try:
            observation_alerts = [
                uuid.UUID(str(alert_id)) for alert_id in observation.get("alert_ids") or []
            ]
        except (TypeError, ValueError):
            continue
        observations.append(
            CorrelationObservation(
                observation_id=observation_key,
                role=observation.get("role"),
                alert_ids=observation_alerts,
                techniques=[str(t) for t in observation.get("techniques") or []],
                first_seen=observation.get("first_seen"),
                last_seen=observation.get("last_seen"),
                time_quality=observation.get("time_quality"),
            )
        )
    return observations


@router.post(
    "/candidates/{candidate_key}/create",
    response_model=CorrelationCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Promote a candidate into a case",
)
async def create_case_from_candidate(
    candidate_key: str,
    db: DBSession,
    user: Annotated[CurrentUser, Depends(require_correlation_writer())],
    scope_body: CandidateScopeRequest | None = None,
) -> CorrelationCaseResponse:
    """Analyst-accepted promotion of a discovered candidate.

    Candidates are computed on demand, never stored, so promoting one means
    re-running discovery and handing its member alerts to the same case writer
    the correlation engine uses. Re-running is deliberate: alerts may have been
    claimed or cased by another owner between the analyst opening the modal and
    clicking create, and promoting a stale member list would steal evidence.

    ``scope_body`` carries the exclusions the analyst made in the inspect view,
    so "drop this noisy alert, then create the case" happens in one server-side
    step: the noisy alert is never claimed, and the observation bundle the case
    receives matches the graph the analyst approved.

    Guarantees the writer already enforces apply unchanged: tenant scoping on
    every alert, deduplicated alerts dropped, UUID case identity, and new cases
    starting in ``new``.
    """
    discovery = CandidateDiscovery(
        db,
        lookback_hours=getattr(settings, "correlation_lookback_hours", 72),
    )
    candidates = await discovery.run(str(user.tenant_id))
    candidate = next(
        (c for c in candidates if c["candidate_key"] == candidate_key), None
    )
    if candidate is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "candidate_not_found", "candidate_key": candidate_key},
        )

    if scope_body and (scope_body.excluded_alert_ids or scope_body.filters):
        try:
            parsed_scope = parse_filters(scope_body.filters)
        except ScopeError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error": "invalid_scope_filter", "reason": str(exc)},
            ) from exc
        scoped = await resolve_scope(
            db,
            user.tenant_id,
            candidate.get("alert_ids", []),
            excluded_ids=scope_body.excluded_alert_ids,
            filters=parsed_scope,
        )
        candidate = await _apply_scope(discovery, user.tenant_id, candidate, scoped)

    try:
        alert_ids = [uuid.UUID(str(alert_id)) for alert_id in candidate.get("alert_ids", [])]
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_candidate_alert_ids"},
        ) from exc
    if not alert_ids:
        raise HTTPException(
            status_code=422,
            detail={"error": "candidate_has_no_alerts", "candidate_key": candidate_key},
        )

    observations = candidate_observations(candidate)

    body = CreateCaseFromCorrelationRequest(
        campaign_key=candidate_key,
        campaign_theme=candidate.get("campaign_theme"),
        score=int(candidate.get("score") or 0),
        normalizer_version="candidate-promotion",
        related_alert_ids=alert_ids,
        severity=candidate.get("severity") or "medium",
        mitre_techniques=list(candidate.get("techniques") or []),
        observations=observations,
        source="candidate-promotion",
    )
    return await create_case_from_correlation(body, db, user)


@router.post("/candidates/{candidate_key}/dismiss", status_code=200)
async def dismiss_candidate(
    candidate_key: str,
    db: DBSession,
    user: AuthUser,
):
    """
    Dismiss a candidate for 24 hours.
    Analyst says "not interested right now" → don't show in list today.

    **Response:**
    - 200 OK: Dismissal recorded
    - 404: Candidate not found
    """

    from sqlalchemy import insert

    tenant_id = user.tenant_id

    # Insert dismissal record
    stmt = insert(CaseCandidateDismissal).values(
        tenant_id=str(tenant_id),
        candidate_key=candidate_key,
        dismissed_at=datetime.now(UTC),
    )

    try:
        await db.execute(stmt)
        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e)) from e

    return {
        "status": "dismissed",
        "candidate_key": candidate_key,
        "dismissed_until": (datetime.now(UTC) + timedelta(hours=24)).isoformat(),
    }


# Phase 2: Suggestions & Attach Endpoints
# ────────────────────────────────────────────────────────────────────────────


class SuggestionResponse(BaseModel):
    """Related alert recommended for attaching to case."""
    alert_id: str
    title: str
    severity: str
    score: int
    entity_overlap: int
    technique_overlap: int
    created_at: datetime
    reason: str


class ImpactPreviewResponse(BaseModel):
    """Score impact if we attach this alert."""
    current_score: int
    new_score: int
    delta: int
    reason: str


class AttachAlertsRequest(BaseModel):
    """Request to attach multiple alerts to case."""
    alert_ids: list[str]


@router.get("/{case_id}/suggestions", response_model=list[SuggestionResponse])
async def list_suggestions(
    case_id: str,
    db: DBSession,
    user: AuthUser,
    min_score: int = Query(2, ge=1, description="Minimum suggestion score"),
    limit: int = Query(50, ge=1, le=500),
) -> list[SuggestionResponse]:
    """
    Find alerts related to a case that aren't yet attached.

    **Scoring:**
    - Entity overlap: +1 per matching entity
    - Technique overlap: +2 per matching technique
    - Minimum threshold: score ≥ min_score (default 2)

    **Response:** Sorted by score descending (highest likelihood first)
    """
    from app.services.suggestion_engine import SuggestionEngine

    engine = SuggestionEngine(db)
    suggestions = await engine.find_suggestions(
        str(user.tenant_id),
        case_id,
        min_score=min_score,
        limit=limit,
    )

    return [
        SuggestionResponse(
            alert_id=s["alert_id"],
            title=s["title"],
            severity=s["severity"],
            score=s["score"],
            entity_overlap=s["entity_overlap"],
            technique_overlap=s["technique_overlap"],
            created_at=datetime.fromisoformat(s["created_at"]),
            reason=s["reason"],
        )
        for s in suggestions
    ]


@router.get("/{case_id}/suggestions/{alert_id}/impact", response_model=ImpactPreviewResponse)
async def preview_attach_impact(
    case_id: str,
    alert_id: str,
    db: DBSession,
    user: AuthUser,
) -> ImpactPreviewResponse:
    """
    Preview the correlation score delta if we attach this alert to the case.

    **Response:**
    - current_score: Existing case correlation score
    - new_score: Score after attaching this alert
    - delta: The change (+3, -1, etc.)
    - reason: Human-readable explanation
    """
    from app.services.suggestion_engine import SuggestionEngine

    engine = SuggestionEngine(db)
    impact = await engine.calculate_attach_impact(
        str(user.tenant_id),
        case_id,
        alert_id,
    )

    if not impact:
        raise HTTPException(status_code=404, detail="Case or alert not found")

    return ImpactPreviewResponse(**impact)


@router.post("/{case_id}/alerts/attach", status_code=200)
async def attach_alerts_to_case(
    case_id: str,
    payload: AttachAlertsRequest,
    db: DBSession,
    user: AuthUser,
) -> dict:
    """
    Attach one or more alerts to a case.

    **Request:**
    ```json
    {
      "alert_ids": ["uuid1", "uuid2", "uuid3"]
    }
    ```

    **Response:**
    - Returns updated case details
    - Alerts are marked as attached_via='suggestion'
    - Triggers case update timestamp
    """
    import uuid as uuid_module

    from sqlalchemy import select
    from sqlalchemy import update as sqlalchemy_update

    from app.models.alert import Alert
    from app.models.case import Case

    tenant_id = user.tenant_id

    # Convert case_id string to UUID
    try:
        case_uuid = uuid_module.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID format") from None

    # Verify case exists and belongs to tenant
    case_stmt = select(Case).where(
        and_(
            Case.id == case_uuid,
            Case.tenant_id == tenant_id,
        )
    )
    case_result = await db.execute(case_stmt)
    case = case_result.scalar_one_or_none()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Convert alert_ids to UUID
    alert_uuids = []
    for aid in payload.alert_ids:
        try:
            alert_uuids.append(uuid_module.UUID(aid))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid alert ID: {aid}") from None

    # Update alerts: set case_id and attached_via
    update_stmt = sqlalchemy_update(Alert).where(
        Alert.id.in_(alert_uuids)
    ).values(
        case_id=case_uuid,
        attached_via='suggestion',
        updated_at=datetime.now(UTC),
    )

    try:
        await db.execute(update_stmt)

        # Add alert IDs to case.alert_ids
        existing_ids = set(case.alert_ids or [])
        existing_ids.update(str(aid) for aid in alert_uuids)
        case.alert_ids = list(existing_ids)
        case.updated_at = datetime.now(UTC)

        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to attach alerts: {str(e)}") from e

    return {
        "status": "attached",
        "case_id": case_id,
        "attached_count": len(alert_uuids),
        "case_alert_count": len(case.alert_ids),
    }


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.get("", response_model=CaseListResponse, summary="List cases")
async def list_cases(
    db: DBSession,
    user: AuthUser,
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    assignee: str | None = Query(None),
    #: ``graph_correlation`` | ``agentic_funnel`` | ``manual`` | ``system``.
    creation_method: str | None = Query(None, max_length=40),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> CaseListResponse:
    # Tenant scoping is non-optional. The aisoc_cases table has carried a
    # tenant_id column since migration 012; until P2-W1 the API simply
    # ignored it, exposing every tenant's caseload to every authenticated
    # caller. Anchor the WHERE clause on tenant_id so the filter is always
    # present even when the operator passes no other filters.
    where_clauses = ["tenant_id = :tenant_id"]
    params: dict[str, Any] = {
        "limit": limit,
        "offset": offset,
        "tenant_id": user.tenant_id,
    }
    if status_filter:
        where_clauses.append("status = :status")
        params["status"] = status_filter
    if severity:
        where_clauses.append("severity = :severity")
        params["severity"] = severity
    if assignee:
        where_clauses.append("assignee = :assignee")
        params["assignee"] = assignee
    if creation_method:
        where_clauses.append("creation_method = :creation_method")
        params["creation_method"] = creation_method

    where_sql = " AND ".join(where_clauses)
    # Status chip totals ignore the status filter (so "All / Open / …" stay
    # meaningful while browsing a filtered page) but keep severity/assignee.
    totals_clauses = ["tenant_id = :tenant_id"]
    totals_params: dict[str, Any] = {"tenant_id": user.tenant_id}
    if severity:
        totals_clauses.append("severity = :severity")
        totals_params["severity"] = severity
    if assignee:
        totals_clauses.append("assignee = :assignee")
        totals_params["assignee"] = assignee
    if creation_method:
        totals_clauses.append("creation_method = :creation_method")
        totals_params["creation_method"] = creation_method
    totals_where = " AND ".join(totals_clauses)

    q = f"""
        SELECT * FROM aisoc_cases
        WHERE {where_sql}
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
    """
    count_q = f"SELECT COUNT(*) AS n FROM aisoc_cases WHERE {where_sql}"
    status_q = f"""
        SELECT status, COUNT(*) AS n
          FROM aisoc_cases
         WHERE {totals_where}
         GROUP BY status
    """
    try:
        rows = await db.execute(text(q).bindparams(**params))
        cases = [_row_to_case(r) for r in rows.fetchall()]
        # Populate rules and alert counts for each case (including deduplicated alerts)
        for case in cases:
            case.rules = await _get_rule_names_for_case(db, user.tenant_id, case.id)
            # Count actual alerts (canonical + deduplicated) that belong to this case
            actual_alert_count = await db.execute(
                text("""
                    SELECT COUNT(*) as count
                    FROM alerts
                    WHERE tenant_id = :tenant_id AND case_id = :case_id
                """).bindparams(tenant_id=user.tenant_id, case_id=case.id)
            )
            count_row = actual_alert_count.fetchone()
            case.alert_count = int(count_row.count) if count_row else 0
        count_params = {k: v for k, v in params.items() if k not in ("limit", "offset")}
        total_row = (await db.execute(text(count_q).bindparams(**count_params))).fetchone()
        total = _row_count(total_row)
        status_rows = (await db.execute(text(status_q).bindparams(**totals_params))).fetchall()
        status_totals: dict[str, int] = {}
        for row in status_rows:
            status_key = _row_field(row, "status", 0)
            if status_key is None:
                continue
            status_totals[str(status_key)] = _row_count(row, count_attr="n", count_index=1)
        page = (offset // limit) + 1 if limit else 1
        pages = max(1, (total + limit - 1) // limit) if limit else 1
        return CaseListResponse(
            cases=cases,
            items=cases,
            total=total,
            limit=limit,
            offset=offset,
            page=page,
            page_size=limit,
            pages=pages,
            status_totals=status_totals,
        )
    except Exception as exc:
        logger.exception("Database error in cases endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


def _row_field(row: Any, attr: str, index: int) -> Any:
    if row is None:
        return None
    if hasattr(row, attr):
        return getattr(row, attr)
    try:
        return row[index]
    except Exception:  # noqa: BLE001 — tuple/mapping fallbacks
        return None


def _row_count(row: Any, *, count_attr: str = "n", count_index: int = 0) -> int:
    raw = _row_field(row, count_attr, count_index)
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED, summary="Create case")
async def create_case(body: CreateCaseRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    import json as _json

    case_id = uuid.uuid4()
    now = datetime.now(UTC)
    # Note: PostgreSQL ``::type`` casts inside text() confuse SQLAlchemy's
    # bind-parameter parser; use ``CAST(:param AS TYPE)`` so the bind survives
    # the round-trip (see also Batch 2 / hunts.py for the same gotcha).
    q = text("""
        INSERT INTO aisoc_cases (
            id, tenant_id, title, description, severity, status, assignee,
            mitre_techniques, alert_ids, compliance_frameworks, tags,
            sla_due_at, opened_at, created_at, updated_at, created_by,
            creation_method
        ) VALUES (
            :id, :tenant_id, :title, :description, :severity, 'new', :assignee,
            CAST(:mitre AS JSONB), CAST(:alert_ids AS UUID[]),
            CAST(:frameworks AS TEXT[]), CAST(:tags AS JSONB),
            :sla, :now, :now, :now, :user,
            'manual'
        ) RETURNING *
    """).bindparams(
        id=case_id,
        tenant_id=user.tenant_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        assignee=body.assignee,
        mitre=_json.dumps(body.mitre_techniques),
        alert_ids=list(map(str, body.alert_ids)) or [],
        frameworks=body.compliance_frameworks or [],
        tags=_json.dumps(body.tags),
        sla=body.sla_due_at,
        now=now,
        user=getattr(user, "email", None) or "system",
    )
    try:
        row = (await db.execute(q)).fetchone()
        if row is None:
            raise HTTPException(status_code=503, detail="Database error: INSERT returned no row")
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in cases endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc

    response = _row_to_case(row)
    # Populate rules from associated alerts
    response.rules = await _get_rule_names(db, user.tenant_id, response.alert_ids)

    # Workstream 8 — fan out to operator-selected ITSM connectors. The
    # case is already persisted (commit above) so a flaky Jira can't
    # block the create. ``fanout_create_case`` swallows per-backend
    # errors into the FanoutResult.status field; we only need to
    # commit the ``case_external_refs`` writes it staged.
    if body.push_to_connector_ids:
        try:
            results = await fanout_create_case(
                db,
                case_row=row,
                tenant_id=user.tenant_id,
                connector_ids=body.push_to_connector_ids,
                pushed_by=getattr(user, "email", None),
                # Operator selected ITSM targets on create ⇒ analyst approval.
                analyst_approved=True,
            )
            await db.commit()
            response.fanout_results = results
        except Exception:
            # Persistence of external refs failed but the AiSOC case
            # itself is fine; surface the partial result and move on.
            logger.exception("cases.create.fanout_persistence_failed case=%s", row.id)
            await db.rollback()
            response.fanout_results = []

    return response


#: A correlation case must stand on at least this many distinct alerts. One
#: alert plus its soft-dedup duplicates is a single detection, not a campaign.
#: The engine applies the same floor (``AISOC_CORRELATION_MIN_CASE_ALERTS``);
#: this is the API-side backstop for older engines and direct callers.
MIN_CORRELATION_CASE_ALERTS = 2


def ensure_new_case_has_evidence(
    *, existing_case_id: uuid.UUID | None, claimable: list[Any]
) -> None:
    """Refuse to open a *new* correlation case from a single alert.

    Extending an existing campaign with one more alert is fine — that case
    already holds evidence. Opening one around a lone alert (its siblings were
    duplicates of it, or already cased) is what produced campaign cases the
    workspace then had to present as an intrusion with one linked alert.
    """
    if existing_case_id is not None or len(claimable) >= MIN_CORRELATION_CASE_ALERTS:
        return
    raise HTTPException(
        status_code=422,
        detail={
            "error": "single_alert_campaign",
            "reason": (
                "correlation needs at least two distinct alerts; a case backed by "
                "one alert plus its duplicates is a single detection, not a campaign"
            ),
            "claimable_alerts": len(claimable),
        },
    )


@router.post(
    "/from-correlation",
    response_model=CorrelationCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or extend a case from correlated evidence",
)
async def create_case_from_correlation(
    body: CreateCaseFromCorrelationRequest,
    db: DBSession,
    user: Annotated[CurrentUser, Depends(require_correlation_writer())],
) -> CorrelationCaseResponse:
    """Create (or extend) a Case from a pre-correlated evidence bundle.

    This is the bypass interface the architecture review flagged as missing: an
    external correlation engine that already knows which alerts belong together
    no longer has to route through the agentic promotion worker.

    Guarantees:

    * **Tenant scoping.** Every alert must belong to the caller's tenant; a
      foreign or unknown id rejects the whole bundle (422) instead of silently
      linking partial evidence.
    * **Deduplicated alerts never become case members.** They are counted in
      ``alerts_ignored`` and dropped.
    * **A campaign has at least two alerts.** A *new* case is refused (422
      ``single_alert_campaign``) when only one distinct alert is claimable; an
      existing campaign may still be extended by a single alert.
    * **UUID case identity.** The row is inserted into ``aisoc_cases`` with a
      UUID and every linked ``alerts.case_id`` is a UUID.
    * **State machine respected.** New cases start in ``new``; existing open
      campaigns are extended, never reopened.
    """
    import json as _json

    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    requested = list(dict.fromkeys(body.related_alert_ids))
    requested_str = [str(a) for a in requested]

    try:
        rows = (
            await db.execute(
                text(
                    """
                    SELECT id, funnel_stage, severity, case_id
                      FROM alerts
                     WHERE tenant_id = :tenant_id
                       AND id = ANY(CAST(:ids AS UUID[]))
                    """
                ).bindparams(tenant_id=user.tenant_id, ids=requested_str)
            )
        ).fetchall()
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in cases.from_correlation")
        raise HTTPException(status_code=503, detail="Database error") from exc

    found = {row.id for row in rows}
    missing = [str(a) for a in requested if a not in found]
    if missing:
        raise HTTPException(
            status_code=422,
            detail={"error": "unknown_or_foreign_alert_ids", "alert_ids": missing[:50]},
        )

    eligible, ignored = partition_correlation_alerts(rows)
    if not eligible:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "no_eligible_alerts",
                "reason": "every supplied alert is funnel_stage='deduplicated'",
                "alerts_ignored": ignored,
            },
        )

    now = datetime.now(UTC)

    try:
        existing = (
            await db.execute(
                text(
                    """
                    SELECT * FROM aisoc_cases
                     WHERE tenant_id = :tenant_id
                       AND created_by = 'correlation-engine'
                       AND status NOT IN ('resolved', 'closed')
                       AND tags->>'campaign_key' = :campaign_key
                     ORDER BY opened_at ASC
                     LIMIT 1
                    """
                ).bindparams(tenant_id=user.tenant_id, campaign_key=body.campaign_key)
            )
        ).fetchone()

        # An alert that already belongs to a *different* case can never be
        # claimed: the claim UPDATE below only accepts ``case_id IS NULL`` or the
        # case being written. Listing such an alert on the new case made it claim
        # evidence it did not own — the workspace showed four linked alerts while
        # the investigation brief, which reads ``alerts.case_id``, correctly
        # showed zero. Partition on ownership instead, and count the foreign ones
        # as ignored.
        target_case_id = existing.id if existing is not None else None
        claimable, cased_elsewhere = partition_claimable_alerts(
            eligible, target_case_id=target_case_id
        )
        ignored += cased_elsewhere
        if not claimable:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "alerts_already_cased",
                    "reason": "every eligible alert already belongs to another case",
                    "alerts_ignored": ignored,
                },
            )
        ensure_new_case_has_evidence(existing_case_id=target_case_id, claimable=claimable)
        eligible_ids = [str(row.id) for row in claimable]

        if existing is not None:
            created = False
            current_severity = str(existing.severity or "medium").lower()
            severity = (
                body.severity
                if severity_rank.get(body.severity, 2) > severity_rank.get(current_severity, 2)
                else current_severity
            )
            row = (
                await db.execute(
                    text(
                        """
                        UPDATE aisoc_cases
                           SET alert_ids = array(
                                 SELECT DISTINCT unnest(alert_ids || CAST(:new_ids AS UUID[]))
                               ),
                               severity = :severity,
                               mitre_techniques = (
                                 SELECT COALESCE(jsonb_agg(DISTINCT v), '[]'::jsonb)
                                   FROM jsonb_array_elements_text(
                                     COALESCE(mitre_techniques, '[]'::jsonb) || CAST(:mitre AS JSONB)
                                   ) AS t(v)
                               ),
                               updated_at = :now
                         WHERE id = :id AND tenant_id = :tenant_id
                        RETURNING *
                        """
                    ).bindparams(
                        id=existing.id,
                        tenant_id=user.tenant_id,
                        new_ids=eligible_ids,
                        severity=severity,
                        mitre=_json.dumps(body.mitre_techniques),
                        now=now,
                    )
                )
            ).fetchone()
            case_id = existing.id
        else:
            created = True
            case_id = uuid.uuid4()
            tags = {
                "campaign_key": body.campaign_key,
                "campaign_theme": body.campaign_theme or "general-intrusion",
                "case_model": "attack_campaign",
                "source": body.source,
                "correlation_score": body.score,
                "normalizer_version": body.normalizer_version,
                "observation_count": len(body.observations),
                "entity_matches": [m.model_dump() for m in body.entity_matches][:50],
                "agentic-promoted": True,
                "reportable": True,
            }
            title = body.title or f"Correlated campaign {body.campaign_key}"[:500]
            description = body.description or (
                f"Created from externally correlated evidence.\n"
                f"campaign_key: {body.campaign_key}\n"
                f"score: {body.score}\n"
                f"observations: {len(body.observations)}\n"
            )
            row = (
                await db.execute(
                    text(
                        """
                        INSERT INTO aisoc_cases (
                            id, tenant_id, title, description, severity, status,
                            mitre_techniques, alert_ids, tags,
                            opened_at, created_at, updated_at, created_by,
                            creation_method
                        ) VALUES (
                            :id, :tenant_id, :title, :description, :severity, 'new',
                            CAST(:mitre AS JSONB), CAST(:alert_ids AS UUID[]),
                            CAST(:tags AS JSONB), :now, :now, :now, 'correlation-engine',
                            'graph_correlation'
                        )
                        RETURNING *
                        """
                    ).bindparams(
                        id=case_id,
                        tenant_id=user.tenant_id,
                        title=title,
                        description=description[:8000],
                        severity=body.severity,
                        mitre=_json.dumps(body.mitre_techniques),
                        alert_ids=eligible_ids,
                        tags=_json.dumps(tags),
                        now=now,
                    )
                )
            ).fetchone()

        claimed_rows = (
            await db.execute(
                text(
                    """
                    UPDATE alerts
                       SET case_id = :case_id,
                           funnel_stage = CASE
                               WHEN funnel_stage IN ('jira_pushed', 'ready_for_jira') THEN funnel_stage
                               ELSE 'cased'
                           END,
                           status = CASE
                               WHEN status IN ('new', 'triaging') THEN 'in_progress'
                               ELSE status
                           END,
                           correlation_state = 'cased',
                           tags = (
                               SELECT COALESCE(jsonb_agg(DISTINCT v), '[]'::jsonb)
                                 FROM jsonb_array_elements_text(
                                   COALESCE(tags, '[]'::jsonb)
                                   || '["agentic-promoted","reportable","correlation-engine"]'::jsonb
                                 ) AS t(v)
                           ),
                           updated_at = :now
                     WHERE tenant_id = :tenant_id
                       AND id = ANY(CAST(:ids AS UUID[]))
                       AND (case_id IS NULL OR case_id = :case_id)
                    RETURNING id
                    """
                ).bindparams(
                    case_id=case_id,
                    tenant_id=user.tenant_id,
                    ids=eligible_ids,
                    now=now,
                )
            )
        ).fetchall()
        linked_ids = [str(claimed_row[0]) for claimed_row in claimed_rows]
        linked = len(linked_ids)

        # Race: another writer can claim a member between the ownership read and
        # this UPDATE. Keep ``aisoc_cases.alert_ids`` equal to the alerts that
        # actually point at the case, so the workspace, the brief and the alerts
        # table can never disagree again.
        if linked < len(eligible_ids):
            await db.execute(
                text(
                    """
                    UPDATE aisoc_cases
                       SET alert_ids = CAST(:ids AS UUID[]), updated_at = :now
                     WHERE id = :id AND tenant_id = :tenant_id
                    """
                ).bindparams(
                    ids=linked_ids, now=now, id=case_id, tenant_id=user.tenant_id
                )
            )

        row = (
            await db.execute(
                text(
                    "SELECT * FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id"
                ).bindparams(id=case_id, tenant_id=user.tenant_id)
            )
        ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=503, detail="Database error: case write returned no row"
            )

        await db.commit()
    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in cases.from_correlation")
        raise HTTPException(status_code=503, detail="Database error") from exc

    # Timeline entry is best-effort and must not fail the create (the case is
    # already committed above).
    if await emit_case_created_from_correlation(
        db,
        case_id=case_id,
        tenant_id=user.tenant_id,
        campaign_key=body.campaign_key,
        score=body.score,
        normalizer_version=body.normalizer_version,
        created=created,
        observations=[o.model_dump() for o in body.observations],
        entity_matches=[m.model_dump() for m in body.entity_matches],
    ):
        try:
            await db.commit()
        except Exception:  # noqa: BLE001
            await db.rollback()
    else:
        await db.rollback()

    base = _row_to_case(row)
    # Populate rules from associated alerts
    base.rules = await _get_rule_names(db, user.tenant_id, base.alert_ids)
    return CorrelationCaseResponse(
        **base.model_dump(),
        created=created,
        alerts_linked=linked,
        alerts_ignored=ignored,
        campaign_key=body.campaign_key,
    )


@router.get("/{case_id}", response_model=CaseResponse, summary="Get case")
async def get_case(case_id: str, db: DBSession, user: AuthUser) -> CaseResponse:
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    row = (
        await db.execute(
            text("SELECT * FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")
    case = _row_to_case(row)
    case.rules = await _get_rule_names_for_case(db, user.tenant_id, case.id)
    # The stored list is the engine's creation-time snapshot; the alerts are the
    # truth. Rebuild it so the header cannot name a technique nothing carries.
    live_mitre = await _get_case_techniques(
        db, user.tenant_id, case.id, list(case.alert_ids or [])
    )
    if live_mitre:
        case.mitre_techniques = live_mitre

    # Count actual alerts (canonical + deduplicated) that belong to this case
    actual_alert_count = await db.execute(
        text("""
            SELECT COUNT(*) as count
            FROM alerts
            WHERE tenant_id = :tenant_id AND case_id = :case_id
        """).bindparams(tenant_id=user.tenant_id, case_id=case.id)
    )
    count_row = actual_alert_count.fetchone()
    case.alert_count = int(count_row.count) if count_row else 0

    return case


@router.patch("/{case_id}", response_model=CaseResponse, summary="Update case")
async def update_case(case_id: str, body: UpdateCaseRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    import json as _json

    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    existing = (
        await db.execute(
            text("SELECT status FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Case not found.")

    if body.status and body.status != existing.status:
        allowed = _TRANSITIONS.get(existing.status, set())
        if body.status not in allowed:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid status transition: {existing.status} → {body.status}. Allowed: {sorted(allowed) or 'none'}",
            )

    now = datetime.now(UTC)
    sets = ["updated_at = :now"]
    params: dict[str, Any] = {
        "id": cid,
        "now": now,
        "tenant_id": user.tenant_id,
    }

    if body.title is not None:
        sets.append("title = :title")
        params["title"] = body.title
    if body.description is not None:
        sets.append("description = :description")
        params["description"] = body.description
    if body.severity is not None:
        sets.append("severity = :severity")
        params["severity"] = body.severity
    if body.assignee is not None:
        sets.append("assignee = :assignee")
        params["assignee"] = body.assignee
    if body.sla_due_at is not None:
        sets.append("sla_due_at = :sla")
        params["sla"] = body.sla_due_at
    if body.mitre_techniques is not None:
        sets.append("mitre_techniques = CAST(:mitre AS JSONB)")
        params["mitre"] = _json.dumps(body.mitre_techniques)
    if body.compliance_frameworks is not None:
        sets.append("compliance_frameworks = CAST(:frameworks AS TEXT[])")
        params["frameworks"] = body.compliance_frameworks
    if body.tags is not None:
        sets.append("tags = CAST(:tags AS JSONB)")
        params["tags"] = _json.dumps(body.tags)

    if body.status:
        sets.append("status = :status")
        params["status"] = body.status
        ts_col = {"triaged": "triaged_at", "resolved": "resolved_at", "closed": "closed_at"}.get(body.status)
        if ts_col:
            sets.append(f"{ts_col} = :now")

    q = text(f"UPDATE aisoc_cases SET {', '.join(sets)} WHERE id = :id AND tenant_id = :tenant_id RETURNING *").bindparams(**params)
    try:
        row = (await db.execute(q)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Case not found.")
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in cases endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc

    response = _row_to_case(row)
    # Populate rules from associated alerts
    response.rules = await _get_rule_names(db, user.tenant_id, response.alert_ids)

    # Workstream 8 — if the operator changed status, project the
    # transition onto every connector this case is already linked to.
    # ``fanout_status_change`` no-ops when the case has no
    # ``case_external_refs`` rows yet, so the call is cheap for
    # AiSOC-only cases.
    if body.status and body.status != existing.status:
        try:
            results = await fanout_status_change(
                db,
                case_row=row,
                tenant_id=user.tenant_id,
                old_status=existing.status,
                new_status=body.status,
                pushed_by=getattr(user, "email", None),
            )
            if results:
                await db.commit()
                response.fanout_results = results
        except Exception:
            logger.exception("cases.update.fanout_persistence_failed case=%s", row.id)
            await db.rollback()
            response.fanout_results = []

        # WS-D2 — when a case enters its terminal lifecycle stages, drop a
        # system note pointing to the auto-summary artifact. The summary
        # itself is generated on-demand by GET /cases/{id}/summary, so this
        # is a cheap, idempotent breadcrumb rather than a heavy precompute.
        if body.status in {"resolved", "closed"}:
            try:
                await _emit_summary_breadcrumb(
                    db,
                    case_id=row.id,
                    tenant_id=user.tenant_id,
                    status=body.status,
                )
            except Exception:  # pragma: no cover — defensive: never block status change.
                logger.exception("cases.update.summary_breadcrumb_failed case=%s", row.id)
                await db.rollback()

    return response


@router.post("/{case_id}/alerts", response_model=CaseResponse, summary="Link alerts to a case")
async def add_alerts(case_id: str, body: AddAlertsRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    """Link alerts to a case **and claim them**.

    Appending to ``aisoc_cases.alert_ids`` without setting ``alerts.case_id``
    made the console and the investigation brief disagree: the workspace listed
    the alerts, the brief (which joins on ``alerts.case_id``) never saw them, and
    another case could claim them later. Alerts already owned by a different
    case are refused rather than silently listed, and unknown/foreign tenant ids
    are not linked at all.
    """
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    ids_str = [str(a) for a in body.alert_ids]
    try:
        claimable = (
            await db.execute(
                text(
                    """
                    UPDATE alerts
                       SET case_id = :case_id,
                           updated_at = now()
                     WHERE tenant_id = :tenant_id
                       AND id = ANY(CAST(:ids AS UUID[]))
                       AND (case_id IS NULL OR case_id = :case_id)
                    RETURNING id
                    """
                ).bindparams(
                    case_id=cid, tenant_id=user.tenant_id, ids=ids_str
                )
            )
        ).fetchall()
        claimed = [row[0] for row in claimable]
        if not claimed:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "no_linkable_alerts",
                    "reason": (
                        "every requested alert is unknown, belongs to another "
                        "tenant, or already belongs to another case"
                    ),
                },
            )

        q = text("""
            UPDATE aisoc_cases
            SET alert_ids = array(
                  SELECT DISTINCT unnest(
                    COALESCE(alert_ids, ARRAY[]::uuid[]) || CAST(:new_ids AS UUID[])
                  )
                ),
                updated_at = now()
            WHERE id = :id AND tenant_id = :tenant_id
            RETURNING *
        """).bindparams(id=cid, new_ids=[str(a) for a in claimed], tenant_id=user.tenant_id)
        row = (await db.execute(q)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found.")
        await db.commit()
        return _row_to_case(row)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in cases endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.post("/{case_id}/observables", response_model=CaseResponse, summary="Update observable graph")
async def update_observables(case_id: str, body: UpdateObservablesRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    import json as _json

    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    existing = (
        await db.execute(
            text("SELECT observable_graph FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=cid, tenant_id=user.tenant_id
            )
        )
    ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Case not found.")

    graph: dict[str, Any] = dict(existing.observable_graph or {})
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    existing_ids = {n["id"] for n in nodes}
    for n in body.nodes:
        if n.id not in existing_ids:
            nodes.append(n.model_dump())
        else:
            nodes = [n.model_dump() if x["id"] == n.id else x for x in nodes]

    edge_keys = {(e["source"], e["target"]) for e in edges}
    for e in body.edges:
        if (e.source, e.target) not in edge_keys:
            edges.append(e.model_dump())

    graph = {"nodes": nodes, "edges": edges}
    q = text(
        "UPDATE aisoc_cases SET observable_graph = CAST(:g AS JSONB), updated_at = now() "
        "WHERE id = :id AND tenant_id = :tenant_id RETURNING *"
    ).bindparams(id=cid, g=_json.dumps(graph), tenant_id=user.tenant_id)
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return _row_to_case(row)
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in cases endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.post("/{case_id}/comments", response_model=CommentResponse, status_code=201, summary="Add comment")
async def add_comment(case_id: str, body: AddCommentRequest, db: DBSession, user: AuthUser) -> CommentResponse:
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    exists = (
        await db.execute(
            text("SELECT 1 FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Case not found.")

    comment_id = uuid.uuid4()
    now = datetime.now(UTC)
    # Stamp the row with tenant_id so the comment table is independently
    # tenant-scoped — see migration 044.
    q = text("""
        INSERT INTO aisoc_case_comments
            (id, case_id, tenant_id, author, body, is_system, created_at)
        VALUES
            (:id, :case_id, :tenant_id, :author, :body, :sys, :now)
        RETURNING *
    """).bindparams(
        id=comment_id,
        case_id=cid,
        tenant_id=user.tenant_id,
        author=getattr(user, "email", None) or "system",
        body=body.body,
        sys=body.is_system,
        now=now,
    )
    try:
        row = (await db.execute(q)).fetchone()
        if row is None:
            raise HTTPException(status_code=503, detail="Database error: INSERT returned no row")
        await db.commit()
        return CommentResponse(
            id=row.id,
            case_id=row.case_id,
            author=row.author,
            body=row.body,
            is_system=row.is_system,
            created_at=row.created_at,
        )
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in cases endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.get("/{case_id}/comments", response_model=list[CommentResponse], summary="List case comments")
async def list_comments(case_id: str, db: DBSession, user: AuthUser) -> list[CommentResponse]:
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    rows = (
        await db.execute(
            text("SELECT * FROM aisoc_case_comments WHERE case_id = :id AND tenant_id = :tenant_id ORDER BY created_at").bindparams(
                id=cid, tenant_id=user.tenant_id
            )
        )
    ).fetchall()
    return [
        CommentResponse(id=r.id, case_id=r.case_id, author=r.author, body=r.body, is_system=r.is_system, created_at=r.created_at)
        for r in rows
    ]


# Alias `/notes` → `/comments` so the web console (which calls `/notes` for the
# "Add Note" affordance) hits the same backing store.  Keeping both routes
# avoids a behavior change for any existing integration that already speaks
# `/comments`.
@router.get("/{case_id}/notes", response_model=list[CommentResponse], summary="List case notes (alias of /comments)")
async def list_notes(case_id: str, db: DBSession, user: AuthUser) -> list[CommentResponse]:
    return await list_comments(case_id, db, user)


@router.post("/{case_id}/notes", response_model=CommentResponse, status_code=201, summary="Add case note (alias of /comments)")
async def add_note(case_id: str, body: AddCommentRequest, db: DBSession, user: AuthUser) -> CommentResponse:
    return await add_comment(case_id, body, db, user)


# ─────────────────────────────────────────────────────────────────────────────
# Linked alerts
#
# ``aisoc_cases.alert_ids`` only carries raw UUIDs, which are useless in the
# workspace's left rail. This endpoint joins them back to the canonical
# ``alerts`` table so the rail can render title / severity / verdict / time in
# one tenant-scoped query instead of N per-alert lookups.
# ─────────────────────────────────────────────────────────────────────────────


def _coerce_alert_ids(values: Any) -> list[uuid.UUID]:
    """Normalise a case's ``alert_ids`` column into UUIDs.

    ``aisoc_cases.alert_ids`` is ``UUID[]`` on a migrated install but older
    rows (migration 001) carried a JSONB array of strings, so both shapes reach
    this helper. Anything unparseable is dropped rather than 500-ing the rail.
    """
    ids: list[uuid.UUID] = []
    for raw in values or []:
        try:
            ids.append(uuid.UUID(str(raw)))
        except (AttributeError, TypeError, ValueError):
            continue
    return ids


#: Resolves one alert's Splunk ``search_name``.
#:
#: ``alerts.rule_name`` is the canonical column (issue #568), but alerts ingested
#: before it existed carry the search name only in ``llm_payload.rule_name``, and
#: for Splunk notables ``alerts.title`` mirrors the ``search_name`` too. Reading
#: all three keeps a case's rule breakdown complete for older evidence instead of
#: reporting a pile of "unknown" rules. The query that uses this must select
#: ``FROM alerts`` (the table name is referenced unaliased).
_SEARCH_NAME_SQL = (
    "COALESCE("
    "NULLIF(btrim(alerts.rule_name), ''), "
    "NULLIF(btrim(alerts.llm_payload ->> 'rule_name'), ''), "
    "NULLIF(btrim(alerts.title), ''), "
    "'unknown')"
)

#: Five-tier severity ladder, highest first — used to pick a rule's worst alert.
_SEVERITY_ORDER: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _one_line(value: Any, limit: int = 220) -> str | None:
    """Collapse a multi-line AI rationale into one clamped summary line."""
    if value is None:
        return None
    text_value = " ".join(str(value).split())
    if not text_value:
        return None
    return text_value if len(text_value) <= limit else f"{text_value[: limit - 1]}…"


class CaseAlertItem(BaseModel):
    id: str
    title: str
    #: Splunk ``search_name`` this alert fired from (see ``_SEARCH_NAME_SQL``).
    search_name: str | None = None
    severity: str
    status: str | None = None
    # Analyst verdict (`true_positive` / `false_positive` / `escalate` / …).
    disposition: str | None = None
    funnel_stage: str | None = None
    confidence: int | None = None
    created_at: datetime | None = None
    # One-line triage rationale (`ai_summary`, falling back to the narrative).
    # The brief's old "Linked alert reports" column carried this per alert; the
    # rail is now the only per-alert surface, so the summary moves with it.
    summary: str | None = None


@router.get(
    "/{case_id}/alerts",
    response_model=list[CaseAlertItem],
    summary="Alerts linked to a case (id, title, severity, verdict, time)",
)
async def list_case_alerts(case_id: str, db: DBSession, user: AuthUser) -> list[CaseAlertItem]:
    """Return every alert attached to the case, newest first.

    Sourced from ``aisoc_cases.alert_ids`` so the list always matches the
    ``Linked alerts (N)`` count the header shows. Alerts missing from the
    ``alerts`` table (deleted / pruned) are dropped rather than rendered as
    bare UUIDs.
    """
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    alert_ids = (
        await db.execute(
            text("SELECT alert_ids FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=cid, tenant_id=user.tenant_id
            )
        )
    ).scalar()
    if alert_ids is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    ids = _coerce_alert_ids(alert_ids)
    if not ids:
        return []

    rows = (
        (
            await db.execute(
                text(
                    "SELECT id, title, severity, status, disposition, funnel_stage, "
                    "confidence, created_at, ai_summary, narrative, "
                    f"{_SEARCH_NAME_SQL} AS search_name FROM alerts "
                    "WHERE tenant_id = :tenant_id AND id IN :ids"
                ).bindparams(bindparam("ids", expanding=True)),
                {"tenant_id": user.tenant_id, "ids": ids},
            )
        )
        .mappings()
        .all()
    )

    return [
        CaseAlertItem(
            id=str(r["id"]),
            title=str(r["title"] or ""),
            search_name=str(r["search_name"] or "") or None,
            severity=str(r["severity"] or "medium"),
            status=r["status"],
            disposition=r["disposition"],
            funnel_stage=r["funnel_stage"],
            confidence=r["confidence"],
            created_at=r["created_at"],
            summary=_one_line(r["ai_summary"] or r["narrative"]),
        )
        for r in rows
    ]


class CaseRuleItem(BaseModel):
    """One Splunk ``search_name`` and every alert it contributed to the case."""

    search_name: str
    alert_count: int
    #: Worst severity among this rule's member alerts (five-tier ladder).
    severity: str = "info"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    alert_ids: list[str] = Field(default_factory=list)


class CaseRuleListResponse(BaseModel):
    case_id: str
    total_alerts: int
    total_rules: int
    rules: list[CaseRuleItem] = Field(default_factory=list)


@router.get(
    "/{case_id}/rules",
    response_model=CaseRuleListResponse,
    summary="Splunk search names (rules) behind a case",
)
async def list_case_rules(case_id: str, db: DBSession, user: AuthUser) -> CaseRuleListResponse:
    """Group a case's alerts by the ``search_name`` they fired from.

    A graph-correlation case is built from *observations*, not rules, so nothing
    in the case payload says how many distinct analytics actually contributed —
    twelve alerts can come from twenty search names. This is the breakdown behind
    the console's Rules tab and the ``N rules`` counters: one row per
    search_name with its alert count, worst severity and time window.
    """
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    alert_ids = (
        await db.execute(
            text(
                "SELECT alert_ids FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id"
            ).bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).scalar()
    if alert_ids is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    ids = _coerce_alert_ids(alert_ids)
    if not ids:
        return CaseRuleListResponse(case_id=str(cid), total_alerts=0, total_rules=0)

    rows = (
        (
            await db.execute(
                text(
                    "SELECT id, severity, created_at, "
                    f"{_SEARCH_NAME_SQL} AS search_name FROM alerts "
                    "WHERE tenant_id = :tenant_id AND id IN :ids"
                ).bindparams(bindparam("ids", expanding=True)),
                {"tenant_id": user.tenant_id, "ids": ids},
            )
        )
        .mappings()
        .all()
    )

    groups: dict[str, CaseRuleItem] = {}
    for row in rows:
        name = str(row["search_name"] or "unknown")
        item = groups.get(name)
        if item is None:
            item = CaseRuleItem(search_name=name, alert_count=0, severity="info")
            groups[name] = item
        item.alert_count += 1
        item.alert_ids.append(str(row["id"]))
        severity = str(row["severity"] or "info").lower()
        if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(item.severity, 0):
            item.severity = severity
        seen = row["created_at"]
        if seen is not None:
            if item.first_seen is None or seen < item.first_seen:
                item.first_seen = seen
            if item.last_seen is None or seen > item.last_seen:
                item.last_seen = seen

    rules = sorted(groups.values(), key=lambda item: (-item.alert_count, item.search_name.lower()))
    return CaseRuleListResponse(
        case_id=str(cid),
        total_alerts=len(ids),
        total_rules=len(rules),
        rules=rules,
    )


@router.get("/{case_id}/evidence", response_model=EvidenceReport, summary="Export evidence chain report")
async def evidence_report(case_id: str, db: DBSession, user: AuthUser) -> EvidenceReport:
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    row = (
        await db.execute(
            text("SELECT * FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")
    return EvidenceReport(
        case_id=row.id,
        title=row.title,
        severity=row.severity,
        status=row.status,
        alert_count=len(row.alert_ids or []),
        mitre_techniques=_coerce_mitre(row.mitre_techniques),
        compliance_frameworks=list(row.compliance_frameworks or []),
        evidence_chain=list(row.evidence_chain or []),
        generated_at=datetime.now(UTC),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Timeline
#
# A flattened activity stream that the case workspace renders on the right.
# We synthesize the timeline from the case's own state transitions, linked
# alerts, comments, and tasks so the front end gets one unified view without
# orchestrating four separate calls.
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/{case_id}/timeline", response_model=TimelineResponse, summary="Case activity timeline")
async def case_timeline(case_id: str, db: DBSession, user: AuthUser) -> TimelineResponse:
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    case_row = (
        await db.execute(
            text("SELECT * FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not case_row:
        raise HTTPException(status_code=404, detail="Case not found.")

    events: list[TimelineEvent] = []

    # Case creation event
    events.append(
        TimelineEvent(
            id=f"case-{case_row.id}-created",
            type="created",
            timestamp=case_row.created_at,
            title="Case opened",
            description=case_row.title,
            actor=case_row.assignee,
        )
    )

    # Status / severity reflection (we only surface the latest snapshot here;
    # full audit history is available via the audit log endpoints).
    if case_row.updated_at and case_row.updated_at != case_row.created_at:
        events.append(
            TimelineEvent(
                id=f"case-{case_row.id}-status",
                type="status_change",
                timestamp=case_row.updated_at,
                title=f"Status: {case_row.status}",
                description=f"Severity {case_row.severity}",
                actor=case_row.assignee,
            )
        )

    # Comments
    comment_rows = (
        await db.execute(
            text(
                "SELECT id, author, body, is_system, created_at "
                "FROM aisoc_case_comments "
                "WHERE case_id = :id AND tenant_id = :tenant_id "
                "ORDER BY created_at"
            ).bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchall()
    for c in comment_rows:
        events.append(
            TimelineEvent(
                id=f"comment-{c.id}",
                type="comment",
                timestamp=c.created_at,
                title="System note" if c.is_system else "Comment",
                description=(c.body or "")[:280],
                actor=c.author,
            )
        )

    # Linked alerts, newest 25. These used to be looked up one-by-one against
    # `aisoc_alerts` — a table that does not exist (the canonical one is
    # `alerts`), so every lookup threw and the swallowed exception silently
    # dropped every linked alert from the timeline. One batched, tenant-scoped
    # query is both correct and cheaper.
    linked_ids = _coerce_alert_ids(case_row.alert_ids)
    if linked_ids:
        try:
            alert_rows = (
                (
                    await db.execute(
                        text(
                            "SELECT id, title, severity, created_at FROM alerts "
                            "WHERE tenant_id = :tenant_id AND id IN :ids "
                            "ORDER BY created_at DESC LIMIT 25"
                        ).bindparams(bindparam("ids", expanding=True)),
                        {"tenant_id": user.tenant_id, "ids": linked_ids},
                    )
                )
                .mappings()
                .all()
            )
            for a in alert_rows:
                events.append(
                    TimelineEvent(
                        id=f"alert-{a['id']}",
                        type="alert_linked",
                        timestamp=a["created_at"] or case_row.created_at,
                        title=f"Alert linked: {a['title']}",
                        description=f"Severity {a['severity']}",
                        actor=None,
                    )
                )
        except Exception as exc:  # noqa: BLE001 — demos may ship without the alerts table
            logger.warning("case timeline: linked-alert lookup failed: %s", safe_log_value(str(exc)))

    # Tasks
    try:
        task_rows = (
            await db.execute(
                text(
                    "SELECT id, title, status, assignee, created_at "
                    "FROM aisoc_case_tasks "
                    "WHERE case_id = :id AND tenant_id = :tenant_id "
                    "ORDER BY created_at"
                ).bindparams(id=cid, tenant_id=user.tenant_id)
            )
        ).fetchall()
        for t in task_rows:
            events.append(
                TimelineEvent(
                    id=f"task-{t.id}",
                    type="task",
                    timestamp=t.created_at,
                    title=f"Task ({t.status}): {t.title}",
                    description=None,
                    actor=t.assignee,
                )
            )
    except Exception:  # noqa: BLE001 — table created by migration 027; tolerate absence
        logger.exception("aisoc_case_tasks not available; skipping task events")

    events.sort(key=lambda e: e.timestamp)
    return TimelineResponse(events=events)


class CaseScopeRequest(BaseModel):
    """Saved alert scope for a case's correlation analysis."""

    excluded_alert_ids: list[str] = Field(default_factory=list)
    filters: list[str] = Field(
        default_factory=list,
        description="llm_payload scope filters: field|op|value|include|exclude",
    )


async def _case_evidence(
    db: Any, cid: uuid.UUID, tenant_id: Any
) -> tuple[Any, list[str]]:
    """The case row plus every alert that belongs to it (including deduplicated).

    Reads both sources deliberately: ``aisoc_cases.alert_ids`` is the fast list
    the console renders while ``alerts.case_id`` is the ownership truth. They
    are kept in step by the writers (migration 081) but a case created before
    that reconcile can disagree, and a correlation view that silently drops the
    difference would hide evidence.

    The union is therefore *ownership-aware*, not blind: a cached id is kept
    when the alert still exists and is either unowned (a writer has not stamped
    it yet) or points at this case. An id that now belongs to a **different**
    case is dropped — otherwise a stale entry would drag another case's alerts
    into this graph and make the evidence look like something it is not.

    NOTE: Deduplicated alerts (funnel_stage='deduplicated') ARE included in the
    evidence set. They are case members in the database and part of the full
    evidence picture (though they are soft-collapsed duplicates, they still
    contribute to the timeline and entity graph).
    """

    row = (
        await db.execute(
            text(
                "SELECT id, title, severity, status, alert_ids, created_at "
                "FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id"
            ).bindparams(id=cid, tenant_id=tenant_id)
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")

    cached_ids = {str(value) for value in (row.alert_ids or [])}
    owned = (
        await db.execute(
            text(
                "SELECT id, case_id FROM alerts "
                "WHERE tenant_id = :tenant_id "
                "  AND (case_id = :id OR id::text = ANY(:cached))"
            ).bindparams(
                id=cid,
                tenant_id=tenant_id,
                cached=sorted(cached_ids) or [""],
            )
        )
    ).all()

    alert_ids = {str(member.id) for member in owned if member.case_id == cid}
    for member in owned:
        if member.case_id is None and str(member.id) in cached_ids:
            alert_ids.add(str(member.id))

    # Third source: soft-dedup **losers**. The correlation engine only links the
    # canonical winner to the case and marks the losers `deduplicated_into:<winner>`
    # in their tags, never `case_id`. Without this join the campaign reads as 9
    # alerts in the graph while the narrative that opened the case describes 114
    # — the modal then rebuilds a graph that cannot explain its own header. A
    # loser is evidence for this case only through a winner that is already in
    # the set, so the join is anchored on ``alert_ids`` rather than on tags alone.
    if alert_ids:
        losers = (
            await db.execute(
                text(
                    "SELECT a.id FROM alerts a "
                    "CROSS JOIN unnest(CAST(:winners AS text[])) AS w(winner) "
                    "WHERE a.tenant_id = :tenant_id "
                    "  AND a.funnel_stage = 'deduplicated' "
                    "  AND a.tags @> to_jsonb(ARRAY['deduplicated_into:' || w.winner])"
                ).bindparams(tenant_id=tenant_id, winners=sorted(alert_ids))
            )
        ).all()
        alert_ids |= {str(member.id) for member in losers}

    return row, sorted(alert_ids)


async def _load_case_scope(
    db: Any, cid: uuid.UUID, tenant_id: Any
) -> tuple[list[str], list[str]]:
    """Read the saved scope for a case (empty when none was saved yet)."""

    row = (
        await db.execute(
            text(
                "SELECT excluded_alert_ids, filters FROM case_alert_scopes "
                "WHERE case_id = :id AND tenant_id = :tenant_id"
            ).bindparams(id=cid, tenant_id=tenant_id)
        )
    ).fetchone()
    if not row:
        return [], []
    return (
        [str(value) for value in (row.excluded_alert_ids or [])],
        [str(value) for value in (row.filters or [])],
    )


@router.get(
    "/{case_id}/correlation",
    response_model=CandidateDetail,
    summary="Correlation graph and scoring for a case's evidence",
)
async def case_correlation(
    case_id: str,
    db: DBSession,
    user: AuthUser,
    exclude: str | None = Query(
        None,
        description=(
            "Comma-separated alert ids to exclude for this request only "
            "(the saved scope is applied first)"
        ),
    ),
    flt: list[str] | None = Query(
        None,
        description=(
            "Repeatable transient alert-scope filter: "
            "'llm_payload.<path>|op|value|include|exclude'"
        ),
    ),
    observations: str | None = Query(
        None,
        description=(
            "Graph projection for observations: 'node' (hub nodes, default) or "
            "'edge' (each observation drawn as a role edge between its entities)"
        ),
    ),
) -> CandidateDetail:
    """The same inspect payload a candidate gets, resolved for a case.

    Graph-engine cases and analyst-approved candidates must be explained the
    same way or the two surfaces drift; this endpoint therefore rebuilds the
    component from the case's own alerts through :class:`CandidateDiscovery`
    and returns the identical model.

    The saved scope (``PUT /cases/{id}/correlation/scope``) and any transient
    ``exclude`` / ``flt`` parameters are applied **server side**, so the graph,
    the pair scores and the timeline always describe the same reduced evidence.
    """

    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    row, evidence_ids = await _case_evidence(db, cid, user.tenant_id)

    stored_excluded, stored_filters = await _load_case_scope(db, cid, user.tenant_id)
    transient_excluded, transient_filters = _parse_scope_request(exclude, flt)
    excluded = sorted({*stored_excluded, *transient_excluded})
    filters = list(dict.fromkeys([*stored_filters, *transient_filters]))
    try:
        parsed = parse_filters(filters)
    except ScopeError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_scope_filter", "reason": str(exc)},
        ) from exc

    discovery = CandidateDiscovery(
        db,
        lookback_hours=getattr(settings, "correlation_lookback_hours", 72),
    )
    scoped = await resolve_scope(
        db, user.tenant_id, evidence_ids, excluded_ids=excluded, filters=parsed
    )
    payload = await discovery.describe_alert_set(
        user.tenant_id, scoped.kept_ids, observation_mode=_observation_mode(observations)
    )
    if payload is None:
        payload = _empty_component({"severity": row.severity}, scoped.kept_ids)

        # For legacy funnel cases (no correlation observations), populate timeline
        # directly from alerts so the modal can display them
        if scoped.kept_ids:
            alert_rows = (
                await db.execute(
                    text("""
                        SELECT id, created_at, event_time, severity, title,
                               llm_payload, mitre_techniques, funnel_stage
                        FROM alerts
                        WHERE tenant_id = :tenant_id
                          AND id::text = ANY(:ids)
                        ORDER BY created_at
                    """).bindparams(
                        tenant_id=user.tenant_id,
                        ids=scoped.kept_ids
                    )
                )
            ).fetchall()

            timeline = []
            for alert_row in alert_rows:
                timeline.append({
                    "alert_id": str(alert_row.id),
                    "observation_key": None,
                    "title": alert_row.title,
                    "payload_title": payload_rule_title(alert_row.llm_payload, alert_row.title),
                    "severity": alert_row.severity,
                    "time": alert_row.event_time or alert_row.created_at,
                    "techniques": list(alert_row.mitre_techniques or []),
                    "funnel_stage": alert_row.funnel_stage,
                    "deduplicated": alert_row.funnel_stage == "deduplicated",
                })
            payload["timeline"] = timeline

    # Rules are counted over the same evidence the Alerts tab lists, not over the
    # case's canonical members: a rule carried by 56 dedup losers used to read
    # ``1`` here while the Alerts tab showed 56 rows for it. Ids are resolved
    # against the pre-scope available set, so excluding a rule can be undone.
    kept = set(scoped.kept_ids)
    rule_alert_ids = await _get_rule_alert_ids(db, user.tenant_id, list(scoped.known_ids))
    payload["rules"] = {
        rule: count
        for rule, count in (
            (rule, sum(1 for alert_id in ids if alert_id in kept))
            for rule, ids in rule_alert_ids.items()
        )
        if count > 0
    }
    payload["rule_alert_ids"] = rule_alert_ids
    # Canonical membership, as opposed to the wider evidence set above.
    payload["member_alert_count"] = len(row.alert_ids or [])

    return _detail_model(
        payload,
        candidate_key=f"case:{cid}",
        campaign_theme=str(row.title or "CASE_EVIDENCE"),
        scope=CandidateScopeEcho(
            excluded_alert_ids=excluded,
            filters=filters,
            dropped=[
                ScopeDrop(
                    alert_id=str(item["alert_id"]),
                    title=item.get("title"),
                    reason=str(item.get("reason") or "excluded"),
                )
                for item in scoped.dropped
            ],
            available_alert_count=len(scoped.known_ids),
        ),
    )


@router.put(
    "/{case_id}/correlation/scope",
    response_model=CandidateScopeEcho,
    summary="Save the alert scope for a case's correlation view",
)
async def save_case_correlation_scope(
    case_id: str,
    body: CaseScopeRequest,
    db: DBSession,
    user: Annotated[CurrentUser, Depends(require_correlation_writer())],
) -> CandidateScopeEcho:
    """Persist which alerts the analyst excluded from this case's analysis.

    Nothing is deleted: the alerts stay case evidence, they are only removed
    from the correlation view (and from anything derived from it). Filters are
    validated here so a bad path is rejected at save time rather than silently
    matching nothing later.
    """

    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    _row, evidence_ids = await _case_evidence(db, cid, user.tenant_id)

    try:
        parsed = parse_filters(body.filters)
    except ScopeError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_scope_filter", "reason": str(exc)},
        ) from exc

    excluded = sorted({str(value) for value in body.excluded_alert_ids if str(value).strip()})
    filters = filters_to_raw(parsed)

    await db.execute(
        text(
            """
            INSERT INTO case_alert_scopes (
                case_id, tenant_id, excluded_alert_ids, filters, created_at, updated_at
            ) VALUES (
                :case_id, :tenant_id, CAST(:excluded AS JSONB), CAST(:filters AS JSONB), now(), now()
            )
            ON CONFLICT (case_id) DO UPDATE SET
                excluded_alert_ids = EXCLUDED.excluded_alert_ids,
                filters = EXCLUDED.filters,
                updated_at = now()
            """
        ).bindparams(
            case_id=cid,
            tenant_id=user.tenant_id,
            excluded=json.dumps(excluded),
            filters=json.dumps(filters),
        )
    )
    await db.commit()

    scoped = await resolve_scope(
        db, user.tenant_id, evidence_ids, excluded_ids=excluded, filters=parsed
    )
    return CandidateScopeEcho(
        excluded_alert_ids=excluded,
        filters=filters,
        dropped=[
            ScopeDrop(
                alert_id=str(item["alert_id"]),
                title=item.get("title"),
                reason=str(item.get("reason") or "excluded"),
            )
            for item in scoped.dropped
        ],
        available_alert_count=len(scoped.known_ids),
    )


@router.get("/{case_id}/graph", response_model=GraphResponse, summary="Entity correlation graph for case (Phase 3)")
async def case_graph(case_id: str, db: DBSession, user: AuthUser) -> GraphResponse:
    """
    Get the entity correlation graph for a case.

    Returns nodes (entities) and edges (relationships) that can be visualized
    with Cytoscape.js or similar graph visualization libraries.

    Phase 3 feature: Provides visual representation of entity correlations
    extracted from case alerts.
    """
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    case_row = (
        await db.execute(
            text("SELECT alert_ids FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not case_row:
        raise HTTPException(status_code=404, detail="Case not found.")

    alert_ids = list(case_row.alert_ids or [])
    if not alert_ids:
        return GraphResponse(nodes=[], edges=[], total_entities=0)

    # Get alerts to extract entities
    try:
        alerts = (
            await db.execute(
                text(
                    "SELECT id, title, severity, affected_hosts, affected_users, affected_ips, affected_domains "
                    "FROM aisoc_alerts "
                    "WHERE id IN ({ids}) AND tenant_id = :tenant_id".format(
                        ids=",".join([f"'{aid}'" for aid in alert_ids[:100]])
                    )
                ).bindparams(tenant_id=user.tenant_id)
            )
        ).fetchall()
    except Exception:
        # If query fails, return empty graph
        return GraphResponse(nodes=[], edges=[], total_entities=0)

    # Extract entities and build node/edge lists
    nodes_dict: dict[str, dict] = {}
    edges_dict: dict[tuple, dict] = {}

    for alert in alerts:
        # Collect all entities from alert
        entities = []

        for field in [alert.affected_hosts, alert.affected_users, alert.affected_ips, alert.affected_domains]:
            if isinstance(field, list):
                entities.extend(field)

        # Create nodes for each entity
        for entity in entities:
            if entity not in nodes_dict:
                entity_type = "unknown"
                if entity.startswith("admin@") or "@" in entity:
                    entity_type = "user"
                elif entity.replace(".", "").replace("-", "").isdigit():
                    entity_type = "ip"
                elif "." in entity:
                    entity_type = "domain"
                else:
                    entity_type = "host"

                nodes_dict[entity] = {
                    "id": entity,
                    "label": entity,
                    "entity_type": entity_type,
                    "severity": alert.severity,
                    "count": 1,
                }
            else:
                # Increment count if entity seen multiple times
                nodes_dict[entity]["count"] += 1
                # Update severity to highest
                if alert.severity in ["critical", "high"] and nodes_dict[entity]["severity"] not in ["critical", "high"]:
                    nodes_dict[entity]["severity"] = alert.severity

        # Create edges between entities within same alert
        for i, entity_a in enumerate(entities):
            for entity_b in entities[i + 1 :]:
                edge_key = tuple(sorted([entity_a, entity_b]))
                if edge_key not in edges_dict:
                    edges_dict[edge_key] = {
                        "source": edge_key[0],
                        "target": edge_key[1],
                        "relationship_type": "co-appears",
                        "strength": 1.0,
                    }
                else:
                    # Increase strength if entities appear together multiple times
                    edges_dict[edge_key]["strength"] = min(1.0, edges_dict[edge_key]["strength"] + 0.1)

    # Convert to response format
    nodes = [
        GraphNode(
            id=n["id"],
            label=n["label"],
            entity_type=n["entity_type"],
            severity=n.get("severity"),
            count=n["count"],
        )
        for n in nodes_dict.values()
    ]

    edges = [
        GraphEdge(
            source=e["source"],
            target=e["target"],
            relationship_type=e["relationship_type"],
            strength=e["strength"],
        )
        for e in edges_dict.values()
    ]

    return GraphResponse(
        nodes=nodes,
        edges=edges,
        total_entities=len(nodes_dict),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tasks
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/{case_id}/tasks", response_model=list[TaskResponse], summary="List case tasks")
async def list_tasks(case_id: str, db: DBSession, user: AuthUser) -> list[TaskResponse]:
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    exists = (
        await db.execute(
            text("SELECT 1 FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Case not found.")
    rows = (
        await db.execute(
            text(
                "SELECT id, title, status, assignee, due_at, created_at "
                "FROM aisoc_case_tasks "
                "WHERE case_id = :id AND tenant_id = :tenant_id "
                "ORDER BY created_at"
            ).bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchall()
    return [_row_to_task(r) for r in rows]


@router.post("/{case_id}/tasks", response_model=TaskResponse, status_code=201, summary="Create task")
async def create_task(
    case_id: str,
    body: CreateTaskRequest,
    db: DBSession,
    user: AuthUser,
) -> TaskResponse:
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    exists = (
        await db.execute(
            text("SELECT 1 FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Case not found.")

    task_id = uuid.uuid4()
    now = datetime.now(UTC)
    try:
        row = (
            await db.execute(
                text(
                    """
                    INSERT INTO aisoc_case_tasks
                        (id, case_id, tenant_id, title, status, assignee, due_at, created_at, updated_at, created_by)
                    VALUES
                        (:id, :case_id, :tenant_id, :title, :status, :assignee, :due_at, :now, :now, :created_by)
                    RETURNING id, title, status, assignee, due_at, created_at
                    """
                ).bindparams(
                    id=task_id,
                    case_id=cid,
                    tenant_id=user.tenant_id,
                    title=body.title,
                    status=body.status,
                    assignee=body.assignee,
                    due_at=body.due_at,
                    now=now,
                    created_by=getattr(user, "email", None) or "system",
                )
            )
        ).fetchone()
        await db.commit()
        return _row_to_task(row)
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in cases endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.patch("/{case_id}/tasks/{task_id}", response_model=TaskResponse, summary="Update task")
async def update_task(
    case_id: str,
    task_id: uuid.UUID,
    body: UpdateTaskRequest,
    db: DBSession,
    user: AuthUser,
) -> TaskResponse:
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    sets: list[str] = []
    params: dict[str, Any] = {
        "id": task_id,
        "case_id": cid,
        "tenant_id": user.tenant_id,
        "now": datetime.now(UTC),
    }
    if body.title is not None:
        sets.append("title = :title")
        params["title"] = body.title
    if body.status is not None:
        sets.append("status = :status")
        params["status"] = body.status
    if body.assignee is not None:
        sets.append("assignee = :assignee")
        params["assignee"] = body.assignee
    if body.due_at is not None:
        sets.append("due_at = :due_at")
        params["due_at"] = body.due_at
    if not sets:
        raise HTTPException(status_code=400, detail="No fields to update.")
    sets.append("updated_at = :now")

    try:
        row = (
            await db.execute(
                text(
                    f"""
                    UPDATE aisoc_case_tasks
                    SET {", ".join(sets)}
                    WHERE id = :id AND case_id = :case_id AND tenant_id = :tenant_id
                    RETURNING id, title, status, assignee, due_at, created_at
                    """
                ).bindparams(**params)
            )
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Task not found.")
        await db.commit()
        return _row_to_task(row)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in cases endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


# ─────────────────────────────────────────────────────────────────────────────
# Investigation proxy
#
# The investigation orchestrator lives in the agents service. The web console
# only knows about /api/v1/cases/{id}/..., so we proxy through and keep the
# external API surface stable.
# ─────────────────────────────────────────────────────────────────────────────


async def _agents_proxy(
    method: str,
    path: str,
    *,
    tenant_id: str | uuid.UUID | None = None,
    **kwargs: Any,
) -> httpx.Response:
    safe_path = _validate_agents_path(path)
    url = f"{_AGENTS_URL}{safe_path}"
    timeout = kwargs.pop("timeout", 30.0)
    if tenant_id is not None:
        try:
            headers = dict(kwargs.pop("headers", {}))
            headers.update(signed_tenant_headers(tenant_id))
            kwargs["headers"] = headers
        except AgentsTenantAuthError as exc:
            raise HTTPException(status_code=503, detail="Agents tenant authentication is not configured") from exc
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        logger.exception(
            "agents_proxy.request_failed",
            extra={
                "method": safe_log_value(method),
                "path": safe_log_value(safe_path),
            },
        )
        raise HTTPException(
            status_code=503,
            detail=f"Agents service unavailable: {exc}",
        ) from exc


@router.post("/{case_id}/investigate", summary="Launch investigation for case")
async def case_investigate(
    case_id: str,
    body: InvestigateRequest,
    db: DBSession,
    user: AuthUser,
) -> dict[str, Any]:
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    exists = (
        await db.execute(
            text("SELECT 1 FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=cid, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Case not found.")

    # Forward the authenticated tenant so the agents service attributes the run
    # to the real tenant instead of falling back to the "default" placeholder,
    # which the demo seed no longer maps to any tenant (issue #601). The ledger
    # is scoped by tenant_id, so without this the whole run is never persisted.
    resp = await _agents_proxy(
        "POST",
        f"/api/v1/cases/{cid}/investigate",
        tenant_id=user.tenant_id,
        json={"alert_summary": body.alert_summary or "", "tenant_id": str(user.tenant_id)},
    )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()


@router.get("/{case_id}/investigations", summary="List investigation runs for a case")
async def list_case_investigations(
    case_id: str,
    db: DBSession,
    user: AuthUser,
) -> dict[str, Any]:
    """List all investigation runs for a case.

    The agents service is the source of truth.  When it's unreachable we return
    an empty list rather than 503 so the case detail page still renders.
    """
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    try:
        resp = await _agents_proxy(
            "GET",
            f"/api/v1/cases/{cid}/investigations",
            tenant_id=user.tenant_id,
        )
        if resp.status_code == 404:
            return {"runs": []}
        if resp.status_code >= 400:
            return {"runs": []}
        return resp.json()
    except HTTPException:
        # Agents service unavailable — render a soft-empty list instead of 503.
        return {"runs": []}


@router.get("/{case_id}/investigations/{run_id}", summary="Get investigation run")
async def case_investigation_run(
    case_id: str,
    run_id: str,
    user: AuthUser,
) -> dict[str, Any]:
    # URL-encode the user-supplied run_id so it cannot inject `/`, `?`, `#`,
    # CR/LF, or other URL syntax into the proxied path.
    safe_run_id = quote(run_id, safe="")
    resp = await _agents_proxy(
        "GET",
        f"/api/v1/investigations/{safe_run_id}",
        tenant_id=user.tenant_id,
    )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()


# Filename sanitiser for Content-Disposition: keep only safe ASCII so the
# header cannot be split with CR/LF and the value renders consistently.
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def _safe_filename_segment(value: str) -> str:
    """Reduce an identifier to a Content-Disposition-safe filename segment."""
    return _SAFE_FILENAME_RE.sub("_", value)[:64] or "unknown"


# ────────────────────────────────────────────────────────────────────────────
# WS-D2 — auto-summary artifact at investigation close.
# ────────────────────────────────────────────────────────────────────────────

# We keep the breadcrumb body in one place so the system note stays uniform
# across deployments — easier to grep, easier to redact in CI exports.
_SUMMARY_BREADCRUMB_BODY = (
    "Case auto-summary generated. Download from "
    "/api/v1/cases/{case_id}/summary?format=html "
    "(or ?format=json for the structured payload). "
    "For the blameless retrospective, fetch "
    "/api/v1/cases/{case_id}/postmortem?format=html. "
    "Print either page (Ctrl/Cmd-P → Save as PDF) for the runbook archive."
)


async def _emit_summary_breadcrumb(
    db: Any,
    *,
    case_id: uuid.UUID,
    tenant_id: uuid.UUID | str,
    status: str,
) -> None:
    """Drop a system comment pointing to the on-demand summary endpoint.

    Idempotent on repeated status changes — we re-emit only when transitioning
    *into* a terminal state, never on noop updates. The body intentionally
    avoids embedding tenant-specific URLs so the artifact link still works
    behind reverse proxies that rewrite the host.
    """
    body = _SUMMARY_BREADCRUMB_BODY.format(case_id=case_id) + f" (status={status})"
    await db.execute(
        text(
            """
            INSERT INTO aisoc_case_comments
                (id, case_id, tenant_id, author, body, is_system, created_at)
            VALUES (:id, :case_id, :tenant_id, :author, :body, true, :now)
            """
        ).bindparams(
            id=uuid.uuid4(),
            case_id=case_id,
            tenant_id=tenant_id,
            author="aisoc",
            body=body,
            now=datetime.now(UTC),
        )
    )
    await db.commit()


@router.get(
    "/{case_id}/correlation-audit",
    summary="Explainable campaign correlation audit (read-only)",
)
async def case_correlation_audit(
    case_id: str,
    db: DBSession,
    user: AuthUser,
) -> dict[str, Any]:
    """Score every linked alert against the campaign seed — no writes.

    Returns per-link matched entities, score, role (primary/supporting/rejected).
    """
    from app.services.campaign_reconcile import score_case_membership

    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    return await score_case_membership(db, tenant_id=user.tenant_id, case_id=cid)


class ReconcileBody(BaseModel):
    dry_run: bool = Field(default=True, description="When true, only report; no unlinks")


@router.post(
    "/{case_id}/reconcile-correlation",
    summary="Unlink alerts that fail entity-aware campaign correlation",
)
async def case_reconcile_correlation(
    case_id: str,
    db: DBSession,
    user: AuthUser,
    body: ReconcileBody | None = None,
) -> dict[str, Any]:
    """Split false megacases: keep evidenced siblings, unlink the rest.

    Default ``dry_run=true``. Pass ``{\"dry_run\": false}`` to apply.
    """
    from app.services.campaign_reconcile import reconcile_campaign_case

    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    dry = True if body is None else bool(body.dry_run)
    result = await reconcile_campaign_case(
        db,
        tenant_id=user.tenant_id,
        case_id=cid,
        dry_run=dry,
    )
    return result


@router.get(
    "/{case_id}/brief",
    response_model=CaseInvestigationBrief,
    summary="Investigation brief — evidence, alert reports, outcome",
)
async def case_investigation_brief(
    case_id: str,
    db: DBSession,
    user: AuthUser,
) -> CaseInvestigationBrief:
    """Short analyst-facing brief: what we did, evidence, and outcome.

    Distinct from ``/summary`` (archival snapshot) — this is the on-screen
    Case workspace panel answering: incident vs FP, what triage/investigation
    produced, and what to do next.
    """
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    brief = await build_case_investigation_brief(db, cid, tenant_id=user.tenant_id)
    if brief is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return brief


@router.get(
    "/{case_id}/report.md",
    summary="Auto-generated case report (Markdown)",
    response_class=PlainTextResponse,
)
async def case_auto_report_markdown(
    case_id: str,
    db: DBSession,
    user: AuthUser,
) -> PlainTextResponse:
    """Always-available Markdown report for the Case Report tab.

    Built from the same investigation brief as ``/brief`` (outcome, what we
    did, evidence, linked alert reports). Does not require an agent
    investigation run — agent-authored reports remain available under
    ``/investigations/{run_id}/report.md`` when present.
    """
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    brief = await build_case_investigation_brief(db, cid, tenant_id=user.tenant_id)
    if brief is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    markdown = render_case_report_markdown(brief)
    case_label = brief.case_number or str(cid)[:8]
    filename = _safe_filename_segment(f"case-{case_label}-report") + ".md"
    return PlainTextResponse(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )


@router.get(
    "/{case_id}/summary",
    summary="Download the per-case auto-summary (JSON or HTML)",
    response_model=None,
)
async def case_auto_summary(
    case_id: str,
    db: DBSession,
    user: AuthUser,
    format: Literal["json", "html"] = Query(
        "json",
        description=(
            "Response format. ``json`` returns the structured CaseAutoSummary; "
            "``html`` returns a print-ready report (use the browser's "
            "Save-as-PDF affordance for archival)."
        ),
    ),
) -> Any:
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    summary = await build_case_summary(db, cid)
    if summary is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    if format == "html":
        rendered = render_case_summary_html(summary)
        case_label = summary.case.case_number or str(summary.case.case_id)[:8]
        filename = _safe_filename_segment(f"case-{case_label}-summary") + ".html"
        return HTMLResponse(
            content=rendered,
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )

    return summary


@router.get(
    "/{case_id}/postmortem",
    summary="Download the per-case blameless post-mortem (JSON or HTML)",
    response_model=None,
)
async def case_auto_postmortem(
    case_id: str,
    db: DBSession,
    user: AuthUser,
    format: Literal["json", "html"] = Query(
        "json",
        description=(
            "Response format. ``json`` returns the structured CasePostmortem; "
            "``html`` returns a print-ready blameless retrospective (use the "
            "browser's Save-as-PDF affordance for the runbook archive)."
        ),
    ),
) -> Any:
    """Generate a deterministic blameless post-mortem for one case.

    Distinct from ``/summary``: the summary is a snapshot of *what the case
    looks like right now*; the post-mortem is a retrospective oriented around
    *what happened, when did we find out, what did we do, and what should we
    change*. Both are deterministic — same case state in, same artefact out.
    """
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    postmortem = await build_case_postmortem(db, cid)
    if postmortem is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    if format == "html":
        rendered = render_case_postmortem_html(postmortem)
        case_label = postmortem.case.case_number or str(postmortem.case.case_id)[:8]
        filename = _safe_filename_segment(f"case-{case_label}-postmortem") + ".html"
        return HTMLResponse(
            content=rendered,
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )

    return postmortem


async def _proxy_investigation_report(
    *,
    case_id: str,
    run_id: str,
    tenant_id: uuid.UUID | str,
    suffix: str,
    default_media_type: str,
    disposition: str,
) -> Response:
    """Proxy an agents investigation report artifact (``.md`` / ``.html`` / ``.pdf``).

    The Case workspace fetches
    ``/cases/{id}/investigations/{run_id}/report.md`` after a run completes.
    Agents owns the artifact at ``/investigations/{run_id}/report.*``; without
    this proxy the console gets a FastAPI 404 (``{"detail":"Not Found"}``)
    even though the run itself is healthy.
    """
    if suffix not in {"md", "html", "pdf"}:
        raise HTTPException(status_code=400, detail="unsupported_report_format")
    safe_run_id = quote(run_id, safe="")
    resp = await _agents_proxy(
        "GET",
        f"/api/v1/investigations/{safe_run_id}/report.{suffix}",
        tenant_id=tenant_id,
    )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    safe_case_id = _safe_filename_segment(case_id)
    safe_run_id_filename = _safe_filename_segment(run_id)
    filename = f"case-{safe_case_id}-{safe_run_id_filename}.{suffix}"
    return Response(
        content=resp.content,
        media_type=resp.headers.get("content-type", default_media_type),
        headers={
            "Content-Disposition": resp.headers.get(
                "content-disposition",
                f'{disposition}; filename="{filename}"',
            ),
        },
    )


@router.get(
    "/{case_id}/investigations/{run_id}/report.md",
    summary="Download investigation Markdown report",
    response_class=PlainTextResponse,
)
async def case_investigation_markdown(
    case_id: str,
    run_id: str,
    user: AuthUser,
) -> Response:
    return await _proxy_investigation_report(
        case_id=case_id,
        run_id=run_id,
        tenant_id=user.tenant_id,
        suffix="md",
        default_media_type="text/markdown; charset=utf-8",
        disposition="inline",
    )


@router.get(
    "/{case_id}/investigations/{run_id}/report.html",
    summary="Download investigation HTML report",
    response_class=HTMLResponse,
)
async def case_investigation_html(
    case_id: str,
    run_id: str,
    user: AuthUser,
) -> Response:
    return await _proxy_investigation_report(
        case_id=case_id,
        run_id=run_id,
        tenant_id=user.tenant_id,
        suffix="html",
        default_media_type="text/html; charset=utf-8",
        disposition="inline",
    )


@router.get(
    "/{case_id}/investigations/{run_id}/report.pdf",
    summary="Download investigation PDF report",
)
async def case_investigation_pdf(
    case_id: str,
    run_id: str,
    user: AuthUser,
) -> Response:
    return await _proxy_investigation_report(
        case_id=case_id,
        run_id=run_id,
        tenant_id=user.tenant_id,
        suffix="pdf",
        default_media_type="application/pdf",
        disposition="attachment",
    )


@router.get("/{case_id}/related", summary="List related cases (by alert/observable overlap)")
async def list_related_cases(
    case_id: str,
    db: DBSession,
    user: AuthUser,
) -> dict[str, Any]:
    """Return other cases that share alerts or observables with this case.

    This is intentionally a lightweight heuristic — we look for cases that
    overlap on `alert_ids` or share an observable IP/host.  It's the smallest
    thing the case detail page needs to stop 404'ing.
    """
    cid = await _resolve_case_id(case_id, db, user.tenant_id)
    row = (
        await db.execute(
            text("SELECT alert_ids, observable_graph FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=cid, tenant_id=user.tenant_id
            )
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")

    alert_ids = list(row.alert_ids or [])
    related: list[dict[str, Any]] = []

    if alert_ids:
        rows = (
            await db.execute(
                text(
                    """
                    SELECT id, case_number, title, severity, status, created_at
                    FROM aisoc_cases
                    WHERE id <> :id
                      AND tenant_id = :tenant_id
                      AND alert_ids && CAST(:alerts AS UUID[])
                    ORDER BY created_at DESC
                    LIMIT 20
                    """
                ).bindparams(
                    id=cid,
                    tenant_id=user.tenant_id,
                    alerts=[str(a) for a in alert_ids],
                )
            )
        ).fetchall()
        for r in rows:
            related.append(
                {
                    "id": str(r.id),
                    "case_number": r.case_number,
                    "title": r.title,
                    "severity": r.severity or "medium",
                    "status": r.status or "new",
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "reason": "shared_alerts",
                }
            )

    return {"related": related}
