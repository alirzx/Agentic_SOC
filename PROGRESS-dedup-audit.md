# Alert Deduplication — Implementation Progress

**Status:** Stage A+B complete (code + unit tests). Stage C shadow vs prod DB not run. Stage D production activation **blocked on operator approval**.

## Test evidence (this session)

- `services/api`: `pytest tests/test_dedup_three_layer.py tests/test_exact_dedupe.py` → **35 passed**
- `services/fusion`: `pytest tests/test_deduplicator.py tests/test_fingerprint_layer1.py` → **8 passed**

## Activation (do not run without approval)

1. Apply `services/api/migrations/074_three_layer_dedup.sql`
2. Deploy API / fusion / agents / web
3. Canary: `python -m app.scripts.shadow_dedup_compare --tenant-id …`
4. Rollback: `AISOC_ALERT_DEDUP_V2=false` + optional `_down.sql`

## Report

`docs/audits/THREE_LAYER_DEDUP_IMPLEMENTATION_REPORT.md`
