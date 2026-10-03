-- 056_alerts_funnel_stage.sql
--
-- Product funnel stages for the 200–500 alerts/day → Jira path:
--   ingested → triaged | suppressed → investigating → cased →
--   ready_for_jira → jira_pushed
--
-- Writable by fusion/agents (raw SQL) and the API ORM. Indexed for
-- queue filters and the SOC Funnel board.

BEGIN;

ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS funnel_stage VARCHAR(32) NOT NULL DEFAULT 'ingested';

CREATE INDEX IF NOT EXISTS ix_alerts_tenant_funnel_stage
  ON alerts (tenant_id, funnel_stage);

CREATE INDEX IF NOT EXISTS ix_alerts_tenant_disposition_funnel
  ON alerts (tenant_id, disposition, funnel_stage);

COMMENT ON COLUMN alerts.funnel_stage IS
  'Agentic SOC funnel position: ingested|triaged|suppressed|investigating|cased|ready_for_jira|jira_pushed';

COMMIT;
