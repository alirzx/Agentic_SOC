-- Ensure investigation_runs token/cost/iteration columns have Postgres
-- DEFAULTs. ORM create_all historically applied Python-side default=0 only,
-- so raw-SQL writers (agents ledger auto-triage) that omitted the columns
-- hit NOT NULL violations and dead-lettered every fused alert at persist.
ALTER TABLE investigation_runs
    ALTER COLUMN total_tokens SET DEFAULT 0,
    ALTER COLUMN total_cost_usd SET DEFAULT 0,
    ALTER COLUMN iterations SET DEFAULT 0;

UPDATE investigation_runs SET total_tokens = 0 WHERE total_tokens IS NULL;
UPDATE investigation_runs SET total_cost_usd = 0 WHERE total_cost_usd IS NULL;
UPDATE investigation_runs SET iterations = 0 WHERE iterations IS NULL;
