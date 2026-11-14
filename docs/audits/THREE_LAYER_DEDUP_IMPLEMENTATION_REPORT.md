# Three-Layer Alert Deduplication — Implementation Report

**Date:** 2026-11-14  
**Status:** Implemented + unit/regression tested. **Production activation NOT executed** (gated).

## 1. Architecture before → after

| Layer | Before | After |
|-------|--------|-------|
| Event | Fusion fingerprint + Redis NX + WHERE NOT EXISTS (no UNIQUE) | Same fingerprint + **UNIQUE(tenant_id, dedup_hash)** after safe rename of twins; agents skip `fusion_decision=duplicate` |
| Alert soft-dedupe | `title\|severity\|rule\|disposition` (cross-host merge, no window) | **Entity-aware `alert:v1:` key**, 15m window, severity/disposition excluded; occurrences preserved |
| Correlation | `tenant:entity:tactic` Redis/PG; alerts kept | Same engine + membership history + score/reasons metadata; unlink helper; **never soft-hides** |
| Categories | Loose `alerts.category` | Central AlertCategory + IncidentCategory taxonomies with confidence/evidence |

## 2. Files created / modified

### Created
- `services/api/app/services/dedup/` (`alert_identity`, `event_fingerprint`, `correlation`, `categories`, `shadow`, `incident_unlink`)
- `services/api/migrations/074_three_layer_dedup.sql` + `_down.sql`
- `services/api/tests/test_dedup_three_layer.py`
- `services/fusion/tests/test_fingerprint_layer1.py`
- `services/api/app/scripts/shadow_dedup_compare.py`
- This report

### Modified
- `services/api/app/services/exact_dedupe.py` — V2 grouping
- `services/api/app/core/config.py` — feature flags
- `services/api/app/models/alert.py` — new columns
- `services/api/app/services/funnel_stages.py` — label “Alert occurrence”
- `services/fusion/app/models/alert.py` — fingerprint source_instance; IncidentSummary metadata
- `services/fusion/app/services/correlator.py` — membership history / remove_alert
- `services/fusion/app/core/config.py` — correlation score flags
- `services/agents/app/workers/fused_alert_consumer.py` — skip fusion duplicates
- `apps/web/.../SocFunnelBoardView.tsx` — tooltip copy

## 3. Database / migration

Migration `074`:
1. Renames duplicate `(tenant_id, dedup_hash)` losers to `legacy_dup:…` (**no deletes**)
2. Creates `UNIQUE INDEX uq_alerts_tenant_dedup_hash` (excludes `legacy_dup:`)
3. Adds `alert_dedup_key`, `canonical_alert_id`, category columns
4. Creates `alert_occurrences`
5. Extends `fusion_incidents` with correlation + category + lifecycle fields

Rollback: `074_three_layer_dedup_down.sql`

## 4. Event fingerprint

SHA-256 of sorted JSON: `tenant_id + source + source_event_ids` (preferred).  
Optional `source_instance` when present. Fallback without vendor id: rule/title/entities (unchanged core fields for stability).

## 5. Alert fingerprint (Layer 2)

`alert:v1:` + SHA-256 of `{tenant, source, rule, detection_type, security_domain, primary_entity, hosts, users, src/dst ips, hashes}`.  
**Excludes** severity & disposition. Window default **900s**.

## 6. Correlation scoring

Weighted overlap: host 0.35, user 0.30, hash 0.40, domain 0.20, IP (reduced alone), temporal 0.20, tactic 0.15, same-rule bonus 0.05 only with other signals. Threshold 0.55. Same-rule alone → unrelated.

## 7. Taxonomies

Alert: endpoint/network/identity/firewall/web/email/cloud/malware/database/application/data/ti/unknown.  
Incident: ATT&CK-aligned stages + multi_stage/policy/suspicious/unknown. No ATT&CK from title alone.

## 8. Funnel semantics

`deduplicated` = **Alert occurrence** (Layer 2). Correlated alerts stay in their stage with `fusion_incident_id`. Suppressed unchanged.

## 9. Test results (executed)

```
services/api:  tests/test_dedup_three_layer.py + test_exact_dedupe.py  → 35 passed
services/fusion: test_deduplicator.py + test_fingerprint_layer1.py     → 8 passed
```

## 10. Concurrency

Redis `SET NX` race covered by tests; DB UNIQUE prevents twin inserts post-migration.

## 11. Shadow validation

Script: `python -m app.scripts.shadow_dedup_compare --tenant-id <uuid>`  
**Not run against production** in this session (no live DB write/read of prod). Unit shadow helper `compare_grouping` exercised in tests (`false_merges_prevented_by_v2`).

## 12. Production activation status

**NOT ACTIVATED against live Fly/production.**

Code defaults: `AISOC_ALERT_DEDUP_V2=true` (new soft-dedupe logic in API process once deployed).  
DB UNIQUE requires applying migration `074` before relying on constraint.

### Activation procedure (requires explicit operator approval)
1. Backup Postgres.
2. Apply `074_three_layer_dedup.sql` on target DB.
3. Deploy API + fusion + agents + web.
4. Run shadow script on a canary tenant; confirm false-merge count.
5. Monitor duplicate rates / sink conflicts.
6. Rollback: set `AISOC_ALERT_DEDUP_V2=false`; optional down migration.

## 13. Feature flags

| Flag | Default | Purpose |
|------|---------|---------|
| `AISOC_ALERT_DEDUP_V2` | true | Entity-aware soft-dedupe |
| `AISOC_DEDUP_SHADOW` | false | Attach shadow report on dedupe runs |
| `AISOC_ALERT_DEDUP_WINDOW_SECONDS` | 900 | Layer-2 window |
| `AISOC_SKIP_FUSION_DUPLICATE_TRIAGE` | true | Agents skip fusion duplicates |
| `AISOC_CORRELATION_SCORE_ENABLED` | true | Fusion correlator metadata |
| `AISOC_ALERT_DISPLAY_DEDUP` | false | Legacy sink display gate (unchanged) |

## 14. Rollback

1. `AISOC_ALERT_DEDUP_V2=false` → legacy display key.  
2. `AISOC_SKIP_FUSION_DUPLICATE_TRIAGE=false` → prior agent behavior.  
3. Optional SQL down migration (does not restore renamed hashes).

## 15. Known limitations

- Full 50-scenario matrix not all DB-integration tested (no ephemeral Postgres in this run).
- `alert_occurrences` inserts are best-effort until migration applied.
- Fusion correlator still primarily keyed by entity:tactic; pairwise scorer is API-side / metadata.
- Shadow against production data not executed here.
- Tier-2 adaptive engine is a **separate** program (not in this change set).
