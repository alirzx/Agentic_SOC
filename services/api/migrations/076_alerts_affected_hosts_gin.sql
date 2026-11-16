-- 076_alerts_affected_hosts_gin.sql
-- Optional performance helpers for Host-Centric candidate prefilter.
--
-- Exact host matching in application / SQL still uses:
--   lower(rtrim(elem, '.')) = ANY(:norm_hosts)
-- via EXISTS over jsonb_array_elements_text(affected_hosts).
--
-- GIN (jsonb_path_ops) speeds containment prefilters such as
--   affected_hosts @> '["hostname"]'::jsonb
-- when callers can supply the *raw stored* string form. Normalized
-- lower/rtrim equality cannot use this GIN alone — keep tenant_id +
-- event_time predicates first (idx_alerts_tenant / idx_alerts_event_t).
--
-- DO NOT run against Production from agent sessions — apply via normal
-- migration release process only. Rollback: DROP INDEX IF EXISTS ...

BEGIN;

CREATE INDEX IF NOT EXISTS ix_alerts_affected_hosts_gin
  ON alerts USING GIN (affected_hosts jsonb_path_ops);

-- Supporting composite for host-centric discovery window scans.
CREATE INDEX IF NOT EXISTS ix_alerts_tenant_event_uncased
  ON alerts (tenant_id, event_time DESC)
  WHERE case_id IS NULL;

COMMENT ON INDEX ix_alerts_affected_hosts_gin IS
  'Host-centric campaign discovery prefilter (campaign-corr:v2); exact match still normalized in app/SQL.';

COMMENT ON INDEX ix_alerts_tenant_event_uncased IS
  'Speeds host-centric / funnel sibling window queries for uncased alerts.';

COMMIT;
