# Tier-2 Adaptive Investigation Engine — Final Delivery Report

**Date:** 2026-11-14  
**Feature flag:** `AISOC_TIER2_ADAPTIVE` (default **OFF**)  
**Production activation:** **NOT performed**

---

## Architecture

### Before

```text
Investigate / Tier-2 Runbook
  → extract_alert_ips
  → if empty: EARLY EXIT (no correlation, no case)
  → find_related_alert_ids (IP only)
  → aggregate_into_case (requires siblings)
  → 5 IP-centric runbook steps
```

### After (when flag ON)

```text
Alert Context Extraction
  → Universal Entity Extraction (P1)
  → Security Domain Profile Selection (P2, multi-profile)
  → Entity-aware Correlation (P3, scored + explained)
  → Case Management Policy (P4: create|extend|standalone|review)
  → Adaptive Investigation + Report (P5)
  → 8-stage Runbook UI (P6)
```

When flag OFF: legacy IP-pivot path unchanged.  
When `AISOC_TIER2_ADAPTIVE_SHADOW=1`: adaptive evaluates without Case mutations; legacy remains authoritative.

### New component responsibilities

| Component | Role |
|-----------|------|
| `tier2_adaptive/entities.py` | Typed entity extraction + provenance |
| `tier2_adaptive/profiles.py` | 8 domain profiles + multi-select |
| `tier2_adaptive/correlation.py` | Explainable scoring 0–100 |
| `tier2_adaptive/case_policy.py` | create/extend/standalone/review (no IP gate) |
| `tier2_adaptive/investigation.py` | Profile steps + structured report |
| `tier2_adaptive/engine.py` | Orchestrator + 8-stage runbook emit |
| `tier2_adaptive/feature_flags.py` | Path selection + shadow |
| `apps/web/src/lib/tier2-adaptive.ts` | UI helpers / status vocabulary |

---

## Implementation

### Files created

- `services/api/app/services/tier2_adaptive/__init__.py`
- `services/api/app/services/tier2_adaptive/entities.py`
- `services/api/app/services/tier2_adaptive/profiles.py`
- `services/api/app/services/tier2_adaptive/correlation.py`
- `services/api/app/services/tier2_adaptive/case_policy.py`
- `services/api/app/services/tier2_adaptive/investigation.py`
- `services/api/app/services/tier2_adaptive/engine.py`
- `services/api/app/services/tier2_adaptive/feature_flags.py`
- `services/api/tests/test_tier2_adaptive_p1_entities.py`
- `services/api/tests/test_tier2_adaptive_p2_profiles.py`
- `services/api/tests/test_tier2_adaptive_p3_correlation.py`
- `services/api/tests/test_tier2_adaptive_p4_case_policy.py`
- `services/api/tests/test_tier2_adaptive_p5_investigation.py`
- `services/api/tests/test_tier2_adaptive_p6_ui_contract.py`
- `services/api/tests/test_tier2_adaptive_p7_matrix.py`
- `apps/web/src/lib/tier2-adaptive.ts`
- `apps/web/src/lib/tier2-adaptive.test.ts`
- `docs/tier2-adaptive-delivery-report.md`
- `PROGRESS-tier2-adaptive.md` (updated)

### Files modified

- `services/api/app/core/config.py` — `TIER2_ADAPTIVE_ENABLED`, `TIER2_ADAPTIVE_SHADOW`
- `services/api/app/services/tier2_ip_pivot.py` — route to adaptive when enabled; shadow hook; catalog switch
- `services/api/app/api/v1/endpoints/runbook.py` — 8-stage response, adaptive enrichment, already-ran detection
- `apps/web/src/components/alerts/AlertDetailView.tsx` — adaptive 8-stage UI + entity/correlation/case panels

### Database changes

**None.** Uses existing `aisoc_cases`, `alerts.enrichment_data` JSON (`tier2_runbook`, `tier2_adaptive`). No migrations.

### API changes

- `GET/POST .../tier2-steps` and `tier2-pivot` remain compatible.
- When adaptive has run: response may include `adaptive` meta + 8 steps.
- Legacy 5-step shape preserved when flag OFF / legacy snapshots present.
- Pivot `to_dict()` still exposes `src_ips`/`dest_ips`/`related_alert_ids`/`case_id`.

### UI changes

- Eight stages with status vocabulary: Completed / Partial / Skipped / Failed / Not Available / No Results / Pending.
- Entity display by type with provenance + confidence.
- Profile chips, case decision, correlation explanations, timeline.
- Missing IP is **not** shown as an error.

### Feature flag configuration

| Env | Default | Effect |
|-----|---------|--------|
| `AISOC_TIER2_ADAPTIVE` | OFF | Select adaptive engine |
| `AISOC_TIER2_ADAPTIVE_SHADOW` | OFF | Evaluate adaptive without Case writes |

---

## Testing

### Per-phase results

| Phase | Executed | Passed | Failed | Blocked | Command |
|-------|----------|--------|--------|---------|---------|
| P1 | 18 | 18 | 0 | 0 | `pytest tests/test_tier2_adaptive_p1_entities.py -v` |
| P2 | 18 | 18 | 0 | 0 | `pytest tests/test_tier2_adaptive_p2_profiles.py -v` |
| P3 | 15 | 15 | 0 | 0 | `pytest tests/test_tier2_adaptive_p3_correlation.py -v` |
| P4 | 14 | 14 | 0 | 0 | `pytest tests/test_tier2_adaptive_p4_case_policy.py -v` |
| P5 | 11 | 11 | 0 | 0 | `pytest tests/test_tier2_adaptive_p5_investigation.py -v` |
| P6 API | 8 | 8 | 0 | 0 | `pytest tests/test_tier2_adaptive_p6_ui_contract.py -v` |
| P6 UI | 6 | 6 | 0 | 0 | `npx vitest run src/lib/tier2-adaptive.test.ts` |
| P7 matrix | 18 | 18 | 0 | 0 | `pytest tests/test_tier2_adaptive_p7_matrix.py -v` |
| Legacy Tier-2 | 5 | 5 | 0 | 0 | `pytest tests/test_tier2_ip_pivot.py -v` |

### Full regression command (executed)

```text
python -m pytest tests/test_tier2_adaptive_*.py tests/test_tier2_ip_pivot.py -v
→ 107 passed in 0.95s
```

**No blocked tests.** DB-backed live sibling search is covered by unit correlation + policy; full async DB integration against Fly Postgres was not required for phase gates and was not claimed as executed.

---

## PowerShell Regression

Alert: `Soorin-Endpoint-Powershell Invoke Command` (no IP).

| Check | Result |
|-------|--------|
| Computer → `cao01vw013.cao.ir` | PASS (observed, source_field=Computer) |
| `extracted_host=SH2` separate | PASS (source_field=extracted_host; not merged) |
| User SID | PASS `S-1-5-21-1793179736-1175893981-2474273398-13753` |
| Script path `...\CL_Utility.ps1` | PASS |
| ScriptBlockText available | PASS (evidence, not auto-malicious) |
| Event ID 4104 not inferred from title | PASS |
| IP-independent correlation | PASS (host + SID scoring) |
| Case policy | PASS → `create` (high severity + sufficient evidence) |
| Investigation | PASS Endpoint profile; continues without IP |
| Report | PASS structured report with limitations + findings |

---

## Deployment Readiness

| Item | Status |
|------|--------|
| Feature flag state | **OFF** (safe default) |
| Shadow validation | Unit-covered (`shadow:` idempotency, no create claim) |
| Legacy fallback | Available; catalog remains 5 steps when flag OFF |
| Rollback | Set `AISOC_TIER2_ADAPTIVE=0` / unset; no migration to reverse |
| Production risks | Case create volume for high-severity solos; correlation weight tuning; DB sibling query cost under load |
| Remaining limitations | External EDR/sandbox/API tools return `not_available` until wired; live multi-tenant DB soak not run here |

### Rollback instructions

1. Set `AISOC_TIER2_ADAPTIVE=0` (and unset shadow if set).
2. Redeploy/restart API only if env is baked into the process (no DB rollback needed).
3. UI falls back to whatever steps are in `enrichment_data.tier2_runbook` / legacy catalog.

**Production activation was not performed and is not claimed.**
