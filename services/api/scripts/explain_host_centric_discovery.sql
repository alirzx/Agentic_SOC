-- Staging / local ONLY — never run against Production from agent sessions.
-- Usage (psql):
--   \set tid '00000000-0000-0000-0000-000000000001'
--   \set seed '...'
--   EXPLAIN (ANALYZE, BUFFERS)
--   ... paste query below with binds ...
--
-- Validates that Host-Centric discovery can use tenant + event_time indexes
-- before the JSONB EXISTS host match. Apply migration 076 in non-prod first
-- if testing index usage for ix_alerts_tenant_event_uncased /
-- ix_alerts_affected_hosts_gin.

EXPLAIN (ANALYZE, BUFFERS)
SELECT
    id, title, severity, disposition, case_id,
    affected_hosts, event_time, created_at
  FROM alerts
 WHERE tenant_id = :'tid'::uuid
   AND id <> :'seed'::uuid
   AND case_id IS NULL
   AND COALESCE(event_time, created_at) >= now() - interval '24 hours'
   AND COALESCE(event_time, created_at) <= now() + interval '24 hours'
   AND lower(COALESCE(NULLIF(disposition, ''), '')) = ANY(
         ARRAY['true_positive','needs_review','escalate','likely_tp']::text[]
       )
   AND EXISTS (
         SELECT 1
           FROM jsonb_array_elements_text(COALESCE(affected_hosts, '[]'::jsonb)) AS elem(h)
          WHERE lower(rtrim(elem.h, '.')) = ANY(ARRAY['example-host']::text[])
       )
 ORDER BY id
 LIMIT 100;
