"""The correlation engine: claim → observe → score → case (doc §7).

Cycle outline
-------------
1. **Claim** a batch of alerts atomically (``correlation_owner`` lock). Losing
   the race means another engine owns the alert; we walk away and retry later.
2. **Load context** — every uncased alert in the lookback window, not just the
   claimed ones. Grouping needs the neighbourhood; only *case creation* is
   limited to what we just claimed.
3. **Extract twice.** Weights depend on tenant frequency, and frequency depends
   on extraction, so cycle 1 extracts to measure and cycle 2 extracts with the
   measurement. Both passes are pure functions over in-memory dicts.
4. **Observe & score.** Alerts collapse into observations (graph-based dedup),
   observations are scored pairwise (L1/L2/L3), and θ-gated pairs form
   connected components.
5. **Create.** Each component is canonicalised (soft-dedup losers map to their
   winner), then handed to the API. The engine never writes case rows itself.

An alert with ``time_quality='alert_time_fallback'`` cannot seed a case and
contributes no L2/L3 (doc §3.3) — it may still be *linked* as evidence to a
case seeded by an alert with a real event time.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import settings
from app.normalizer.extract_keys import ExtractedKeys, extract_keys
from app.normalizer.roles import assign_role
from app.safe_db import safe_execute, safe_executemany, safe_fetch, safe_transaction
from app.services.case_client import CaseClient, CaseClientError
from app.services.diagnostics import build_ambient_report, remember
from app.services.frequency import common_values, count_keys, store_frequency
from app.services.graph import GraphProjector
from app.services.observations import Observation, build_observation, group_observations
from app.services.rule_registry import (
    audit_rule_resolution,
    load_rule_identity_maps,
    resolve_rule_identity_map,
)
from app.services.scoring import (
    Component,
    PairScore,
    TenantGraph,
    connected_components,
    score_matrix,
)

logger = structlog.get_logger()

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: How many distinct rules the case summary names before it rolls the rest up
#: into "+N more". The full list lives in the Observations tab; the summary is
#: read in a case header, not in a report appendix.
_MAX_SUMMARY_RULES = 8


def _short_window(first: datetime | None, last: datetime | None) -> str:
    """A one-line time window (``2026-11-12 14:48 → 14:52``)."""
    if first is None:
        return "time window unknown"
    if last is None or last == first:
        return f"first seen {first.strftime('%Y-%m-%d %H:%M')}"
    if first.date() == last.date():
        return f"{first.strftime('%Y-%m-%d %H:%M')} → {last.strftime('%H:%M')}"
    return f"{first.strftime('%Y-%m-%d %H:%M')} → {last.strftime('%Y-%m-%d %H:%M')}"

def case_skip_reason(
    *,
    canonical: Sequence[str],
    claimed: Sequence[str],
    members: Sequence[Observation],
    min_alerts: int,
) -> str | None:
    """Why this component must not open a case (``None`` when it may).

    A case asserts that several *distinct* alerts agree with each other, so the
    floor is counted on the canonical alerts the case would list — not on the
    component's raw alerts, where one detection repeated on twenty hosts looks
    like a campaign, and not on the claimable subset, which ownership may have
    already given to a stronger cluster. Refusing here is what keeps
    "campaign" cases from being opened around a single alert.
    """
    if not claimed:
        # Strong cluster, but every canonical alert already belongs to a case
        # (legacy promoter or an earlier cycle). Reporting this as
        # "below_min" would hide the real reason in ops.
        return "already_owned"
    if len(canonical) < min_alerts:
        return "below_min_case_alerts"
    # A case must be seeded by at least one observation with a real event time
    # (doc §3.3).
    if not any(o.time_quality_ok for o in members):
        return "alert_time_fallback"
    return None


#: Role family → case theme vocabulary (kept aligned with the legacy promoter's
#: themes so the console shows one consistent set of campaign names).
_ROLE_THEME: dict[str, str] = {
    "credential_access": "credential-access",
    "lateral_movement": "lateral-movement",
    "supply_chain": "initial-access",
    "command_and_control": "command-and-control",
    "exfiltration": "exfiltration",
    "privilege_escalation": "privilege-escalation",
    "execution": "execution",
    "persistence": "persistence",
    "impact": "impact",
    "aggregation": "general-intrusion",
    "general": "general-intrusion",
}

_THEME_TITLE: dict[str, str] = {
    "credential-access": "Suspected credential-access campaign",
    "lateral-movement": "Suspected lateral-movement campaign",
    "initial-access": "Suspected initial-access campaign",
    "command-and-control": "Suspected C2 / command-and-control campaign",
    "exfiltration": "Suspected data-exfiltration campaign",
    "privilege-escalation": "Suspected privilege-escalation campaign",
    "execution": "Suspected malware-execution campaign",
    "persistence": "Suspected persistence campaign",
    "impact": "Suspected impact / ransomware campaign",
    "general-intrusion": "Suspected multi-stage intrusion campaign",
}


@dataclass
class CycleResult:
    tenant_id: str
    claimed: int = 0
    context: int = 0
    observations: int = 0
    components: int = 0
    cases_created: int = 0
    cases_reused: int = 0
    alerts_linked: int = 0
    alerts_deduplicated: int = 0
    skipped_no_case: int = 0
    errors: int = 0
    notes: list[str] = field(default_factory=list)
    #: Ambient-key decisions for this cycle (see ``services/diagnostics.py``):
    #: which values were wallpaper and which pairs were refused for sharing
    #: nothing but them. Also cached per tenant for ``GET /v1/diagnostics``.
    diagnostics: dict[str, Any] | None = None

    def as_dict(self, *, include_full_diagnostics: bool = False) -> dict[str, Any]:
        """Convert to dict for logging or serialization.
        
        By default, diagnostics are summarized (counts only) to keep logs compact.
        Set include_full_diagnostics=True to include lists of ambient_keys and vetoed_pairs.
        """
        result = {
            "tenant_id": self.tenant_id,
            "claimed": self.claimed,
            "context": self.context,
            "observations": self.observations,
            "components": self.components,
            "cases_created": self.cases_created,
            "cases_reused": self.cases_reused,
            "alerts_linked": self.alerts_linked,
            "alerts_deduplicated": self.alerts_deduplicated,
            "skipped_no_case": self.skipped_no_case,
            "errors": self.errors,
            "notes": self.notes,
        }
        
        # Log diagnostics summary only (not full lists)
        if self.diagnostics:
            if include_full_diagnostics:
                result["diagnostics"] = self.diagnostics
            else:
                # Compact summary for logs
                result["diagnostics_summary"] = {
                    "ambient_key_count": len(self.diagnostics.get("ambient_keys", [])),
                    "vetoed_pair_count": self.diagnostics.get("vetoed_pair_count", 0),
                    "vetoed_pairs_truncated": self.diagnostics.get("vetoed_pairs_truncated", False),
                }
        
        return result


def as_payload(value: Any) -> dict[str, Any]:
    """Decode a ``llm_payload`` column into a dict.

    asyncpg returns JSONB as ``str`` unless a type codec is registered on the
    pool, and the same row can arrive as a dict in tests. Normalising here keeps
    every downstream call site free of the distinction.
    """
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, (str, bytes, bytearray)):
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return dict(decoded) if isinstance(decoded, Mapping) else {}
    return {}


def _tag_values(tags: Any) -> list[str]:
    """Normalise ``alerts.tags`` which may be a JSON array or an object."""
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except (TypeError, ValueError):
            return []
    if isinstance(tags, list):
        return [str(t) for t in tags]
    if isinstance(tags, Mapping):
        out: list[str] = []
        for key, value in tags.items():
            out.append(str(key))
            if isinstance(value, str):
                out.append(value)
        return out
    return []


def _dedup_target(tags: Any) -> str | None:
    for value in _tag_values(tags):
        if value.startswith("deduplicated_into:"):
            candidate = value.split(":", 1)[1].strip()
            try:
                return str(uuid.UUID(candidate))
            except (ValueError, TypeError):
                return None
    return None


def _role_family(role: str) -> str:
    return role.split(":", 1)[0] if role else "general"


class CorrelationEngine:
    def __init__(
        self,
        pool: Any,
        *,
        graph: GraphProjector | None = None,
        case_client: CaseClient | None = None,
    ) -> None:
        self._pool = pool
        self._graph = graph
        self._client = case_client
        self._owns_client = case_client is None

    # ── database helpers ──────────────────────────────────────────────────
    async def _claim(self, tenant_id: uuid.UUID, limit: int) -> list[uuid.UUID]:
        """Atomically take ownership of unclaimed alerts (doc §7.1).

        ``FOR UPDATE SKIP LOCKED`` plus the ``correlation_owner IS NULL``
        predicate means exactly one engine wins each row, even when the legacy
        promoter is running concurrently.

        The claim TTL exists for one purpose: to retry a cycle that died while
        it owned a row. It must never resurrect *consumed* evidence. Soft-dedup
        losers (``funnel_stage='deduplicated'``) carry no ``case_id`` of their
        own, so before this guard existed the TTL re-claimed them, overwrote
        their terminal ``correlation_state`` with ``claimed``, and the candidate
        queue then offered the campaign that had already been cased as a brand
        new one (all-in-one run: 61 alerts, score 6, next to the case they had
        produced). Terminal states are excluded for the same reason; only an
        in-flight claim past its TTL may be retried.
        """
        rows = await safe_fetch(
            self._pool,
            """
            WITH candidates AS (
                SELECT id
                  FROM alerts
                 WHERE tenant_id = $1
                   AND llm_payload IS NOT NULL
                   AND case_id IS NULL
                   AND COALESCE(disposition, '') NOT IN
                       ('false_positive', 'benign', 'benign_true_positive')
                   AND funnel_stage IS DISTINCT FROM 'deduplicated'
                   AND COALESCE(correlation_state, '') NOT IN
                       ('cased', 'deduplicated_into_case')
                   AND (
                         correlation_owner IS NULL
                      OR (correlation_owner = $2
                          AND correlation_state = 'error')
                      OR (correlation_owner = $2
                          AND correlation_claimed_at < now() - make_interval(mins => $4))
                   )
                 ORDER BY created_at ASC
                 LIMIT $3
                 FOR UPDATE SKIP LOCKED
            )
            UPDATE alerts a
               SET correlation_owner = $2,
                   correlation_claimed_at = now(),
                   correlation_state = 'claimed',
                   normalizer_version = $5,
                   updated_at = now()
              FROM candidates c
             WHERE a.id = c.id
            RETURNING a.id
            """,
            tenant_id,
            settings.owner,
            limit,
            settings.claim_ttl_minutes,
            settings.normalizer_version,
            operation_name="claim_alerts",
        )
        return [row["id"] for row in rows]

    async def _load_context(self, tenant_id: uuid.UUID) -> list[Mapping[str, Any]]:
        rows = await safe_fetch(
            self._pool,
            """
            SELECT id, title, severity, rule_name, funnel_stage, case_id,
                   created_at, tags, llm_payload
              FROM alerts
             WHERE tenant_id = $1
               AND llm_payload IS NOT NULL
               AND case_id IS NULL
               AND COALESCE(disposition, '') NOT IN
                   ('false_positive', 'benign', 'benign_true_positive')
               AND created_at >= now() - make_interval(hours => $2)
             ORDER BY created_at ASC
             LIMIT $3
            """,
            tenant_id,
            settings.lookback_hours,
            settings.max_alerts_per_cycle,
            operation_name="load_context",
        )
        return rows

    async def _load_role_overrides(self, tenant_id: uuid.UUID) -> dict[str, str]:
        rows = await safe_fetch(
            self._pool,
            "SELECT rule_name, role FROM correlation_rule_roles WHERE tenant_id = $1",
            tenant_id,
            operation_name="load_role_overrides",
        )
        return {row["rule_name"]: row["role"] for row in rows}

    # ── extraction ────────────────────────────────────────────────────────
    async def _extract_all(
        self,
        tenant_id: uuid.UUID,
        rows: Sequence[Mapping[str, Any]],
        *,
        freq: Mapping[tuple[str, str], int] | None = None,
        common: Iterable[str] | None = None,
        audit: bool = False,
    ) -> dict[uuid.UUID, ExtractedKeys]:
        out: dict[uuid.UUID, ExtractedKeys] = {}
        resolution_cache: dict[str, Any] = {}
        # One registry read per cycle: resolving per rule name re-scanned the
        # whole map table once per distinct rule, which dominated the cycle.
        registry = await load_rule_identity_maps(self._pool, tenant_id)

        for row in rows:
            payload = as_payload(row["llm_payload"])
            rule_name = str(payload.get("rule_name") or row.get("rule_name") or "").strip()
            if rule_name not in resolution_cache:
                resolution_cache[rule_name] = resolve_rule_identity_map(
                    tenant_id,
                    rule_name,
                    registry,
                )
            resolution = resolution_cache[rule_name]

            identity_map = None
            if resolution.map is not None:
                identity_map = {
                    "host_fields": resolution.map.host_fields,
                    "user_fields": resolution.map.user_fields,
                    "ip_fields": resolution.map.ip_fields,
                    "domain_fields": resolution.map.domain_fields,
                    "hash_fields": resolution.map.hash_fields,
                    "process_guid_fields": resolution.map.process_guid_fields,
                    "excluded_fields": resolution.map.excluded_fields,
                    "field_kind_overrides": resolution.map.field_kind_overrides,
                }

            extracted = extract_keys(
                payload,
                settings.normalizer_version,
                freq=freq,
                common_values=common,
                identity_map=identity_map,
                identity_map_source=resolution.matched_source,
            )
            out[row["id"]] = extracted

            if audit:
                filtered_values: dict[str, list[str]] = {}
                for item in extracted.filtered:
                    reason = str(item.get("reason") or "filtered")
                    value = str(item.get("value") or "")
                    if value:
                        filtered_values.setdefault(reason, []).append(value[:200])

                await audit_rule_resolution(
                    self._pool,
                    tenant_id=tenant_id,
                    alert_id=row["id"],
                    rule_name=rule_name,
                    resolution=resolution,
                    normalizer_version=settings.normalizer_version,
                    resolved_host_fields=resolution.map.host_fields if resolution.map else (),
                    resolved_user_fields=resolution.map.user_fields if resolution.map else (),
                    resolved_ip_fields=resolution.map.ip_fields if resolution.map else (),
                    missing_fields=extracted.missing_fields,
                    filtered_values=filtered_values,
                )
        return out

    def _observations(
        self,
        rows: Sequence[Mapping[str, Any]],
        extracted: Mapping[uuid.UUID, ExtractedKeys],
        overrides: Mapping[str, str],
    ) -> list[Observation]:
        observations: list[Observation] = []
        for row in rows:
            keys = extracted[row["id"]]
            payload = as_payload(row["llm_payload"])
            alert_fields = payload.get("alert_fields") if isinstance(payload, Mapping) else None
            role = assign_role(
                rule_name=str(payload.get("rule_name") or row["rule_name"] or ""),
                alert_fields=alert_fields if isinstance(alert_fields, Mapping) else None,
                techniques=keys.techniques,
                rule_overrides=overrides,
            )
            observations.append(
                build_observation(payload, keys, alert_id=str(row["id"]), role=role)
            )
        return observations

    # ── component → case payload ──────────────────────────────────────────
    def _canonicalise(
        self,
        component: Component,
        by_alert: Mapping[str, Mapping[str, Any]],
    ) -> tuple[list[str], list[str]]:
        """Split members into canonical alerts vs. deduplicated evidence.

        Soft-dedup losers carry ``deduplicated_into:<winner>`` in their tags.
        They stay as *evidence* (they prove an observation repeated) but are
        never case members — that is the documented semantic and what stops a
        case from listing 70 identical notables.
        """
        canonical: list[str] = []
        deduplicated: list[str] = []
        for alert_id in component.alert_ids:
            row = by_alert.get(alert_id)
            if row is None:
                continue
            if str(row["funnel_stage"] or "") == "deduplicated":
                deduplicated.append(alert_id)
                target = _dedup_target(row["tags"])
                # Only the *canonical* alert can represent the group in a case.
                # Pulling in a winner that belongs to another component is
                # handled by the ownership pass in ``run_once``.
                if target and target in by_alert and target not in canonical:
                    canonical.append(target)
                continue
            if alert_id not in canonical:
                canonical.append(alert_id)
        return canonical, deduplicated

    def _campaign_identity(
        self,
        members: Sequence[Observation],
        alert_ids: Sequence[str],
        by_alert: Mapping[str, Mapping[str, Any]],
    ) -> tuple[str, str, str]:
        """Return ``(theme, campaign_key, primary_entity_token)``."""
        role_counts = Counter(_role_family(o.role) for o in members)
        theme = _ROLE_THEME.get(role_counts.most_common(1)[0][0], "general-intrusion")

        # Primary entity: the value shared by the most observations, preferring
        # host > user > ip > domain at equal support.
        priority = {"host": 0, "user": 1, "ip": 2, "domain": 3, "hash": 4, "process_guid": 5}
        support: Counter[str] = Counter()
        weights: dict[str, int] = {}
        for observation in members:
            for key in observation.keys:
                if key.kind not in priority or key.weight < 2:
                    continue
                support[key.token] += 1
                weights[key.token] = max(weights.get(key.token, 0), key.weight)
        if support:
            token = sorted(
                support,
                key=lambda t: (
                    -support[t],
                    -weights.get(t, 0),
                    priority.get(t.split(":", 1)[0], 9),
                    t,
                ),
            )[0]
            kind, _, value = token.partition(":")
            value = value.split("|", 1)[-1]
            return theme, f"{theme}|{kind}:{value}"[:200], token

        # No entity survived filtering — anchor the key on the earliest alert so
        # a case can still be reused deterministically within the window.
        anchor = alert_ids[0] if alert_ids else "none"
        return theme, f"{theme}|alert:{anchor}", ""

    def _build_payload(
        self,
        *,
        tenant_id: uuid.UUID,
        component: Component,
        members: Sequence[Observation],
        canonical: Sequence[str],
        by_alert: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        theme, campaign_key, primary = self._campaign_identity(members, canonical, by_alert)

        severities = [
            str(by_alert[a]["severity"] or "medium").lower() for a in canonical if a in by_alert
        ]
        severity = max(severities, key=lambda s: _SEVERITY_RANK.get(s, 2), default="medium")

        techniques: list[str] = []
        for observation in members:
            for technique in observation.techniques:
                if technique not in techniques:
                    techniques.append(technique)

        hosts: list[str] = []
        users: list[str] = []
        for observation in members:
            hosts.extend(h for h in observation.hosts if "." in h and h not in hosts)
            users.extend(u for u in observation.users if u not in users)

        roles = sorted({o.role for o in members if o.role})
        title_entities = (hosts[:2] + users[:2])[:3]
        title = _THEME_TITLE.get(theme, _THEME_TITLE["general-intrusion"])
        if title_entities:
            title = f"{title} involving {', '.join(title_entities)}"[:500]

        # A short, readable summary — not the observation dump.
        #
        # Every observation used to be concatenated straight into
        # ``description`` (up to 8000 characters, one line per observation,
        # duplicates included), which the case header then rendered as one wall
        # of text. The Observations tab already lists each observation with its
        # alerts, so the description only has to answer "what is this, how big
        # is it, and when", plus a bounded, de-duplicated rule roll-up for
        # anyone reading the case without opening the console.
        ordered = sorted(
            members,
            key=lambda o: (o.first_seen or datetime.min.replace(tzinfo=UTC), o.key),
        )
        first_seen = next((o.first_seen for o in ordered if o.first_seen), None)
        last_seen = next(
            (
                o.last_seen or o.first_seen
                for o in reversed(ordered)
                if (o.last_seen or o.first_seen)
            ),
            None,
        )
        alert_total = sum(len(o.alert_ids) for o in ordered)
        rule_counts: Counter[str] = Counter()
        for observation in ordered:
            for rule in observation.rule_names or [observation.key]:
                rule_counts[rule] += 1

        anchor = f" on {primary}" if primary else ""
        narrative = [
            f"Graph correlation grouped {len(ordered)} observation(s) from {alert_total} alert(s)"
            f"{anchor} into one campaign, {_short_window(first_seen, last_seen)}.",
            "",
            f"Correlation score: {component.score} (L1 entity overlap + L2 context + L3 graph path)",
            f"Observations merged: {len(ordered)}",
            f"Roles: {', '.join(roles) or 'n/a'}",
            f"Primary entity: {primary or 'n/a'}",
        ]
        if rule_counts:
            top_rules = rule_counts.most_common(_MAX_SUMMARY_RULES)
            narrative.append("")
            narrative.append(f"Rules ({len(rule_counts)} distinct):")
            for rule, count in top_rules:
                narrative.append(f"- {rule}" + (f" (×{count})" if count > 1 else ""))
            hidden = len(rule_counts) - len(top_rules)
            if hidden > 0:
                narrative.append(f"- +{hidden} more rule(s), listed in the Observations tab")
        narrative.append("")
        narrative.append(
            "Created by the graph correlation engine (normalizer"
            f" v{settings.normalizer_version}, θ={settings.theta})."
            " Per-observation detail, alert ids and timings live in the Observations tab."
        )

        return {
            "campaign_key": campaign_key,
            "campaign_theme": theme,
            "score": component.score,
            "normalizer_version": settings.normalizer_version,
            "related_alert_ids": [str(a) for a in canonical],
            "title": title,
            "description": "\n".join(narrative)[:2000],
            "severity": severity,
            "mitre_techniques": techniques[:50],
            "entity_matches": _entity_matches(members),
            "observations": [
                {
                    "observation_id": o.key,
                    "role": o.role,
                    "alert_ids": list(o.alert_ids),
                    "techniques": list(o.techniques),
                    "first_seen": o.first_seen.isoformat() if o.first_seen else None,
                    "last_seen": o.last_seen.isoformat() if o.last_seen else None,
                    "time_quality": o.time_quality,
                }
                for o in members
            ],
            "correlated_at": datetime.now(UTC).isoformat(),
            "source": "correlation-engine",
            "tenant_id_hint": str(tenant_id),
        }

    # ── persistence of the engine's own bookkeeping ───────────────────────
    async def _persist_observations(
        self, tenant_id: uuid.UUID, observations: Sequence[Observation]
    ) -> None:
        rows = [
            (
                tenant_id,
                o.key,
                o.alert_ids,
                o.role,
                json.dumps(o.techniques),
                json.dumps(o.hosts),
                json.dumps(o.users),
                json.dumps(o.ips),
                json.dumps(o.domains),
                o.first_seen,
                o.last_seen,
                o.time_quality,
                settings.normalizer_version,
                # Weighted `kind:value` keys. The candidate list rebuilds L3
                # from the ledger, so it needs the same tokens this engine
                # scores — entity buckets alone lose hash / process_guid.
                json.dumps(sorted(o.tokens)),
                # L1 is a weighted sum and L2 is story / kill-chain driven, so
                # the ledger has to carry those inputs too for an offline
                # rebuild to produce the same number.
                json.dumps({k.token: k.weight for k in o.keys if k.weight > 0}),
                json.dumps(list(o.stories)),
                json.dumps(list(o.kill_chain)),
            )
            for o in observations
        ]
        success = await safe_executemany(
            self._pool,
            """
            INSERT INTO correlation_observations
                (tenant_id, observation_key, alert_ids, role, techniques,
                 hosts, users, ips, domains, first_seen, last_seen,
                 time_quality, normalizer_version, tokens, token_weights,
                 stories, kill_chain, created_at, updated_at)
            VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,
                    $10,$11,$12,$13,$14::jsonb,$15::jsonb,$16::jsonb,$17::jsonb,
                    now(), now())
            ON CONFLICT (tenant_id, observation_key)
            DO UPDATE SET alert_ids = ARRAY(
                              -- Union, never replace. `_load_context` only
                              -- returns *uncased* alerts, so overwriting the
                              -- list erased the evidence of every alert that
                              -- had just been attached to a case. The case
                              -- graph then found zero ledger coverage for its
                              -- own alerts and rendered empty.
                              SELECT DISTINCT member
                                FROM unnest(correlation_observations.alert_ids || EXCLUDED.alert_ids)
                                     AS t(member)
                          ),
                          role = EXCLUDED.role,
                          techniques = EXCLUDED.techniques,
                          hosts = EXCLUDED.hosts,
                          users = EXCLUDED.users,
                          ips = EXCLUDED.ips,
                          domains = EXCLUDED.domains,
                          tokens = EXCLUDED.tokens,
                          token_weights = EXCLUDED.token_weights,
                          stories = EXCLUDED.stories,
                          kill_chain = EXCLUDED.kill_chain,
                          first_seen = LEAST(correlation_observations.first_seen, EXCLUDED.first_seen),
                          last_seen = GREATEST(correlation_observations.last_seen, EXCLUDED.last_seen),
                          normalizer_version = EXCLUDED.normalizer_version,
                          updated_at = now()
            """,
            rows,
            operation_name="persist_observations",
        )
        if not success and rows:
            logger.warning("engine.observation_persist_failed", count=len(rows))

    async def _repair_case_coverage(
        self,
        tenant_id: uuid.UUID,
        *,
        freq: Mapping[tuple[str, str], int],
        common: Iterable[str],
    ) -> int:
        """Re-observe cased alerts that the ledger no longer lists.

        The case graph is rebuilt from ``correlation_observations``, and
        ``_load_context`` deliberately skips cased alerts, so a cased alert can
        only stay in the ledger through the union on its *old* row. When that
        row is rewritten under a different key (grouping changed, normalizer
        bump) or lost, the case keeps its alerts but loses their observations:
        ``GET /cases/{id}/correlation`` then renders an empty graph while every
        alert is still there. Measured on the case-2 dataset: 10 of 15 case
        alerts had no ledger row, and the graph fell to one observation at
        score 0.

        Restoring the invariant "every alert with a payload belongs to exactly
        one observation" makes the case view self-healing instead of dependent
        on the history of its rows. Returns the number of alerts re-observed.
        """

        rows = await safe_fetch(
            self._pool,
            """
            SELECT a.id, a.title, a.severity, a.rule_name, a.funnel_stage,
                   a.case_id, a.created_at, a.tags, a.llm_payload
              FROM alerts a
             WHERE a.tenant_id = $1
               AND a.case_id IS NOT NULL
               AND a.llm_payload IS NOT NULL
               AND NOT EXISTS (
                     SELECT 1 FROM correlation_observations o
                      WHERE o.tenant_id = a.tenant_id
                        AND a.id = ANY(o.alert_ids)
                   )
             ORDER BY a.created_at ASC
             LIMIT $2
            """,
            tenant_id,
            settings.max_alerts_per_cycle,
            operation_name="repair_case_coverage",
        )
        if not rows:
            return 0

        try:
            extracted = await self._extract_all(tenant_id, rows, freq=freq, common=common, audit=True)
            overrides = await self._load_role_overrides(tenant_id)
            repaired = group_observations(self._observations(rows, extracted, overrides))
            await self._persist_observations(tenant_id, repaired)
        except Exception as exc:  # noqa: BLE001 — repair is best-effort
            logger.warning("engine.case_coverage_repair_failed", error=str(exc))
            return 0

        covered = sum(len(observation.alert_ids) for observation in repaired)
        logger.info(
            "engine.case_coverage_repaired",
            tenant=str(tenant_id),
            alerts=covered,
            observations=len(repaired),
        )
        return covered

    async def _mark(self, tenant_id: uuid.UUID, alert_ids: Sequence[uuid.UUID], state: str) -> None:
        """Set the engine state, never downgrading a case-linked alert.

        ``no_case`` is a *negative* decision and must never overwrite a
        ``cased`` alert: a soft-dedup winner can be listed as the representative
        of several components, and a later skipped component must not undo the
        case it was already linked to.
        """
        if not alert_ids:
            return
        guard = "AND correlation_state IS DISTINCT FROM 'cased'" if state == "no_case" else ""
        success = await safe_execute(
            self._pool,
            f"""
            UPDATE alerts
               SET correlation_state = $3, updated_at = now()
             WHERE tenant_id = $1 AND id = ANY($2::uuid[])
               AND case_id IS NULL
               {guard}
            """,
            tenant_id,
            list(alert_ids),
            state,
            operation_name=f"mark_alerts_{state}",
        )
        if not success:
            logger.warning("engine.mark_failed", state=state, count=len(alert_ids))

    async def _link_case(
        self,
        tenant_id: uuid.UUID,
        *,
        case_id: str,
        canonical: Sequence[uuid.UUID],
        deduplicated: Sequence[uuid.UUID],
    ) -> None:
        """Write case membership back onto the alerts (single transaction)."""
        async def _transaction_body(conn) -> None:
            if canonical:
                await conn.execute(
                    """
                    UPDATE alerts
                       SET case_id = $3,
                           funnel_stage = CASE
                               WHEN funnel_stage IN ('jira_pushed', 'ready_for_jira') THEN funnel_stage
                               ELSE 'cased'
                           END,
                           correlation_state = 'cased',
                           tags = (
                               SELECT COALESCE(jsonb_agg(DISTINCT v), '[]'::jsonb)
                                 FROM jsonb_array_elements_text(
                                   COALESCE(tags, '[]'::jsonb)
                                   || '["agentic-promoted","reportable","correlation-engine"]'::jsonb
                                 ) AS t(v)
                           ),
                           status = CASE WHEN status IN ('new', 'triaging') THEN 'in_progress' ELSE status END,
                           updated_at = now()
                     WHERE tenant_id = $1 AND id = ANY($2::uuid[])
                    """,
                    tenant_id,
                    list(canonical),
                    uuid.UUID(str(case_id)),
                )
            if deduplicated:
                # Dedup losers stay out of case membership but are marked as
                # consumed by this campaign so they are never re-processed.
                await conn.execute(
                    """
                    UPDATE alerts
                       SET correlation_state = 'deduplicated_into_case',
                           updated_at = now()
                     WHERE tenant_id = $1 AND id = ANY($2::uuid[])
                    """,
                    tenant_id,
                    list(deduplicated),
                )

            # ``aisoc_cases.alert_ids`` is the console's fast list; ownership
            # lives on ``alerts.case_id``. The API can only stamp the ids it
            # received, so an engine write after that call left the two out
            # of step (workspace said 13 linked alerts while 15 alerts
            # pointed at the case). Reconcile the cache from ownership here,
            # inside the same transaction.
            await conn.execute(
                """
                UPDATE aisoc_cases c
                   SET alert_ids = (
                         SELECT COALESCE(array_agg(a.id ORDER BY a.id), '{}'::uuid[])
                           FROM alerts a
                          WHERE a.tenant_id = $1 AND a.case_id = c.id
                       ),
                       updated_at = now()
                 WHERE c.tenant_id = $1 AND c.id = $2
                """,
                tenant_id,
                uuid.UUID(str(case_id)),
            )
        
        success = await safe_transaction(
            self._pool,
            _transaction_body,
            operation_name="link_case",
        )
        if not success:
            logger.warning(
                "engine.link_case_failed",
                case_id=case_id,
                canonical_count=len(canonical),
                dedup_count=len(deduplicated),
            )

    # ── main entry point ──────────────────────────────────────────────────
    async def run_once(self, tenant_id: uuid.UUID | str) -> CycleResult:
        tid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(str(tenant_id))
        result = CycleResult(tenant_id=str(tid))

        claimed = await self._claim(tid, settings.max_alerts_per_cycle)
        result.claimed = len(claimed)

        context = await self._load_context(tid)
        result.context = len(context)
        if not context:
            return result

        by_alert: dict[str, Mapping[str, Any]] = {str(row["id"]): row for row in context}
        overrides = await self._load_role_overrides(tid)

        # Pass 1: measure tenant frequency. Pass 2: extract with that baseline.
        first_pass = await self._extract_all(tid, context)
        freq = count_keys(first_pass.values())
        # The window size matters: a tenant-wide domain can be on every alert
        # here and still sit below the 30-day absolute threshold.
        common = common_values(freq, total_alerts=len(context))
        extracted = await self._extract_all(tid, context, freq=freq, common=common, audit=True)
        result.notes.append(f"freq_values={len(freq)} common={len(common)}")

        def publish_report(
            observations: Sequence[Observation] = (),
            pairs: Sequence[PairScore] = (),
        ) -> dict[str, Any]:
            """Publish (and cache) the ambient report, also on early returns.

            Called twice: once as soon as the ambient set is known, so a cycle
            that ends before scoring still answers "which keys were wallpaper?",
            and again with the scored pairs so the vetoed-pair list is complete.
            """

            report = remember(
                build_ambient_report(
                    tenant_id=str(tid),
                    freq=freq,
                    ambient=common,
                    observations=list(observations),
                    pairs=list(pairs),
                    total_alerts=len(context),
                    theta=settings.theta,
                )
            )
            result.diagnostics = report
            return report

        publish_report()

        await store_frequency(self._pool, tid, freq)

        observations = group_observations(self._observations(context, extracted, overrides))
        result.observations = len(observations)
        if not observations:
            await self._mark(tid, claimed, "no_case")
            publish_report()
            return result

        try:
            await self._persist_observations(tid, observations)
        except Exception as exc:  # noqa: BLE001 — audit table best-effort
            logger.warning("engine.observation_persist_failed", tenant=result.tenant_id, error=str(exc))

        if self._graph is not None and self._graph.enabled:
            for observation in observations:
                await self._graph.upsert_observation(str(tid), observation)

        graph = TenantGraph(observations)
        pairs = score_matrix(observations, graph=graph)
        components = connected_components(observations, pairs, theta=settings.theta)
        result.components = len(components)

        # What the ambient rules decided this cycle. Cheap (pure over data we
        # already have) and the only way to answer "why were these two alerts not
        # merged?" without re-running the engine by hand.
        report = publish_report(observations, pairs)
        if report["ambient_key_count"] or report["vetoed_pair_count"]:
            logger.info(
                "engine.ambient_report",
                tenant=result.tenant_id,
                ambient_keys=report["ambient_key_count"],
                vetoed_pairs=report["vetoed_pair_count"],
            )

        by_observation = {o.key: o for o in observations}
        claimed_set = {str(a) for a in claimed}

        client = self._client
        owns_client = False
        if client is None:
            client = CaseClient()
            await client.__aenter__()
            owns_client = True

        try:
            # A soft-dedup winner can be the canonical representative for losers
            # that sit in *different* components (the winner's own rule forms a
            # different observation than the loser's rule). Without explicit
            # ownership the same alert would be written into two case rows.
            # Direct membership wins; otherwise the highest-scoring component
            # keeps the winner and the others are re-evaluated without it.
            planned: list[tuple[Component, list[Observation], list[str], list[str]]] = []
            for component in components:
                members = [by_observation[k] for k in component.observation_keys if k in by_observation]
                canonical, deduplicated = self._canonicalise(component, by_alert)
                planned.append((component, members, canonical, deduplicated))

            # Components arrive sorted by score, so first-come wins by strength.
            # Preference for "direct membership" was tried and is wrong on
            # heavily-deduplicated corpora: a canonical alert often sits alone
            # in a weak cluster *and* represents the losers of a strong one, and
            # pinning it to the weak cluster prevents the real campaign from
            # forming.
            owner: dict[str, int] = {}
            for index, (_component, _members, canonical, _dedup) in enumerate(planned):
                for alert_id in canonical:
                    owner.setdefault(alert_id, index)

            for index, (component, members, canonical, deduplicated) in enumerate(planned):
                canonical = [a for a in canonical if owner.get(a) == index]

                # Only alerts this cycle claimed may be turned into a case; the
                # rest are context that already belongs to another cycle/case.
                canonical_claimed = [a for a in canonical if a in claimed_set]
                skip_reason = case_skip_reason(
                    canonical=canonical,
                    claimed=canonical_claimed,
                    members=members,
                    min_alerts=settings.min_case_alerts,
                )
                if skip_reason is not None:
                    result.skipped_no_case += len(component.alert_ids)
                    result.notes.append(f"skip_{skip_reason}:{component.score}")
                    # Mark every alert this cycle owns in the component so none
                    # are left dangling in 'claimed' forever.
                    await self._mark(
                        tid,
                        [uuid.UUID(a) for a in component.alert_ids if a in claimed_set],
                        "no_case",
                    )
                    continue

                payload = self._build_payload(
                    tenant_id=tid,
                    component=component,
                    members=members,
                    canonical=canonical,
                    by_alert=by_alert,
                )
                try:
                    response = await client.create_from_correlation(payload)
                    case_id = str(response.get("id") or "")
                    if response.get("created") is False:
                        result.cases_reused += 1
                    else:
                        result.cases_created += 1
                    if not case_id:
                        raise CaseClientError("response missing case id")
                    await self._link_case(
                        tid,
                        case_id=case_id,
                        canonical=[uuid.UUID(a) for a in canonical],
                        deduplicated=[uuid.UUID(a) for a in deduplicated],
                    )
                    result.alerts_linked += len(canonical)
                    result.alerts_deduplicated += len(deduplicated)
                except (CaseClientError, ValueError) as exc:
                    logger.warning(
                        "engine.case_create_failed",
                        tenant=result.tenant_id,
                        campaign_key=payload.get("campaign_key"),
                        error=str(exc),
                    )
                    result.errors += 1
                    await self._mark(tid, [uuid.UUID(a) for a in canonical], "error")

            unclaimed_misses = [
                uuid.UUID(a)
                for a in claimed_set
                if a not in owner and not any(a in c.alert_ids for c in components)
            ]
            await self._mark(tid, unclaimed_misses, "no_case")
        finally:
            if owns_client:
                await client.__aexit__(None, None, None)

        # Runs after case creation on purpose: these alerts already belong to a
        # case, so they must not join this cycle's components or start a new
        # campaign — they only need their evidence back in the ledger.
        try:
            repaired = await self._repair_case_coverage(tid, freq=freq, common=common)
            if repaired:
                result.notes.append(f"case_coverage_repaired={repaired}")
        except Exception as exc:  # noqa: BLE001 — never fail a cycle over a repair
            logger.warning("engine.case_coverage_repair_failed", error=str(exc))

        # Aggregate skip_* notes to keep logs compact (e.g., "skip_already_owned:20" repeated 50x)
        skipped_by_reason: dict[str, int] = {}
        non_skip_notes: list[str] = []
        for note in result.notes:
            if note.startswith("skip_"):
                # Parse "skip_already_owned:123" → ("skip_already_owned", 123)
                parts = note.rsplit(":", 1)
                if len(parts) == 2:
                    reason, score_str = parts
                    try:
                        score = int(score_str)
                        skipped_by_reason[reason] = skipped_by_reason.get(reason, 0) + 1
                    except ValueError:
                        non_skip_notes.append(note)
                else:
                    non_skip_notes.append(note)
            else:
                non_skip_notes.append(note)

        # Rebuild notes: non-skip first, then aggregated skip summary
        result.notes = non_skip_notes
        if skipped_by_reason:
            skip_summary = "; ".join(
                f"{reason}={count}" for reason, count in sorted(skipped_by_reason.items())
            )
            result.notes.append(f"skipped_components: {skip_summary}")

        logger.info("engine.cycle_complete", **result.as_dict())
        return result


def _entity_matches(members: Sequence[Observation]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for observation in members:
        for key in observation.keys:
            if key.weight < 2:
                continue
            token = (key.kind, key.value)
            if token in seen:
                continue
            seen.add(token)
            out.append({"kind": key.kind, "value": key.value})
            if len(out) >= 50:
                return out
    return out


__all__ = ["CorrelationEngine", "CycleResult"]
