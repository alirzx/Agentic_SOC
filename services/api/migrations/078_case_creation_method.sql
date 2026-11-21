-- 075_case_creation_method.sql
--
-- Both case-creation paths stay in service:
--
--   * `agentic_funnel`  — services/agents/app/workers/case_promoter.py
--                         (the original funnel/campaign promoter)
--   * `graph_correlation` — services/correlation (the v2.0 engine) via
--                         POST /api/v1/cases/from-correlation
--
-- Until now the only way to tell them apart was the free-text `created_by`
-- value ('agentic-funnel' vs 'correlation-engine') plus a tag key. That works
-- for a human reading a row but not for reports, filters or an operator
-- asking "which engine produced this case?". This migration makes the origin
-- a first-class, constrained column and backfills every existing row.
--
-- Values:
--   graph_correlation    created by the v2.0 correlation engine
--   agentic_funnel       created by the legacy funnel promoter (incl. backfill)
--   manual               created through POST /api/v1/cases
--   system               created by any other automated writer
--
-- Additive only: no existing column is dropped, renamed or rewritten, so both
-- engines keep running in parallel exactly as before.

BEGIN;

ALTER TABLE aisoc_cases
    ADD COLUMN IF NOT EXISTS creation_method TEXT;

-- Backfill from the conventions in use before this migration. Order matters:
-- the explicit creators win over the generic tag heuristic.
UPDATE aisoc_cases
   SET creation_method = CASE
       WHEN created_by IN ('agentic-funnel', 'agentic-funnel-backfill') THEN 'agentic_funnel'
       WHEN created_by = 'correlation-engine' THEN 'graph_correlation'
       WHEN COALESCE(tags ->> 'source', '') IN ('correlation-engine', 'graph_correlation')
            THEN 'graph_correlation'
       WHEN COALESCE(tags ->> 'source', '') = 'agentic_funnel' THEN 'agentic_funnel'
       WHEN created_by = 'system' THEN 'system'
       ELSE 'manual'
   END
 WHERE creation_method IS NULL;

ALTER TABLE aisoc_cases ALTER COLUMN creation_method SET DEFAULT 'manual';
ALTER TABLE aisoc_cases ALTER COLUMN creation_method SET NOT NULL;

-- Constrain the vocabulary so a typo in a future writer fails loudly instead of
-- silently producing an unfilterable value.
ALTER TABLE aisoc_cases DROP CONSTRAINT IF EXISTS ck_aisoc_cases_creation_method;
ALTER TABLE aisoc_cases ADD CONSTRAINT ck_aisoc_cases_creation_method
    CHECK (creation_method IN ('graph_correlation', 'agentic_funnel', 'manual', 'system'));

COMMENT ON COLUMN aisoc_cases.creation_method IS
    'How the case was created: graph_correlation (v2.0 engine) | agentic_funnel '
    '(legacy promoter) | manual (POST /cases) | system. Both engines run in '
    'parallel; this column is how a case is attributed to one of them.';

-- "Show me the cases each engine produced" is the intended query.
CREATE INDEX IF NOT EXISTS ix_aisoc_cases_creation_method
    ON aisoc_cases (tenant_id, creation_method);

COMMIT;
