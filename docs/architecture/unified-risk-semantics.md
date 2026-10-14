# Unified Risk Semantics (Phase 2 / 2.1)

**Status:** Provisional — not a calibrated probability of attack.

Implementation: `services/agents/app/risk/unified.py` → `assess_unified_risk()`,
which wraps `services/agents/app/runtime/risk.py` → `score_risk()`.

## Independent concepts

| Field | Meaning | Range | Notes |
|---|---|---|---|
| `alert_severity` | Vendor / rule severity ladder | info…critical | Input; not overwritten by risk |
| `detection_confidence` | Triage confidence in the disposition | 0.0–1.0 | From auto-triage / deterministic |
| `incident_confidence` | Strength of multi-alert / correlation hypothesis | 0.0–1.0 | Derived; capped |
| `business_impact` | Asset criticality contribution | 0–20 points | From CMDB enrich when available |
| `risk_score` | Prioritization score | 0–100 | Sum of bounded factors; **not** P(attack) |
| `risk_band` | LOW…EMERGENCY | enum | From `band_for(score)` |
| `investigation_priority` | P4…P0 queue hint | enum | Derived from score |
| `response_urgency` | routine…immediate | enum | Score + detection confidence |

## What risk must NOT do

- Bypass Case promotion gates (`should_promote` / `AISOC_AGENT_AUTO_CASE`).
- Auto-execute playbooks or response actions.
- Treat missing asset / missing IOC as proof of benign or malicious activity.
- Be reported as a statistically validated probability without labeled calibration.

## Calibration limitation (Phase 2.1)

No analyst-labeled offline calibration dataset was available in this environment.
Weights remain **provisional** defaults. Next wave: labeled extract → train/eval
split → PR-AUC / calibration plot → shadow comparison before any threshold change.
