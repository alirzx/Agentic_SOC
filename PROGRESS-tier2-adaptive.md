# Tier-2 Adaptive Investigation Engine

**Status:** ALL PHASES PASSED — ready for controlled activation (`AISOC_TIER2_ADAPTIVE`, default OFF)

**Canvas:** `tier2-adaptive-investigation-plan.canvas.tsx`

| Phase | Status | Notes |
|-------|--------|-------|
| P1 Universal Entity Extraction | PASSED | 18/18 |
| P2 Adaptive Domain Profiles | PASSED | 18/18 |
| P3 Entity-aware Correlation | PASSED | 15/15 |
| P4 Case Management Policy | PASSED | 14/14 |
| P5 Adaptive Investigation + Report | PASSED | 11/11 |
| P6 Tier-2 UI Redesign | PASSED | 8 Python + 6 Vitest |
| P7 Feature Flag + Test Suite | PASSED | 18/18 matrix + 5 legacy + full suite **107 passed** |

## Constraint

Do not change Deduplication. No destructive migrations. Feature-flag rollout (`AISOC_TIER2_ADAPTIVE`, default OFF).

## Activation

```bash
# Controlled enable (non-prod first)
AISOC_TIER2_ADAPTIVE=1

# Shadow (evaluate adaptive, legacy still mutates)
AISOC_TIER2_ADAPTIVE_SHADOW=1

# Immediate rollback
unset AISOC_TIER2_ADAPTIVE
# or AISOC_TIER2_ADAPTIVE=0
```

## Test command (evidence)

```text
cd services/api
python -m pytest tests/test_tier2_adaptive_*.py tests/test_tier2_ip_pivot.py -v
# 107 passed

cd apps/web
npx vitest run src/lib/tier2-adaptive.test.ts
# 6 passed
```

## Production

**Not activated.** Flag remains default OFF. No production deploy/restart performed.
