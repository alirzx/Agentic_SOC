-- 081_case_alert_links_reconcile.sql
--
-- Two columns claim to say which alerts belong to a case:
--
--   * `alerts.case_id`      — ownership, set by every creation path and guarded
--                             by `case_id IS NULL OR case_id = <this case>`
--   * `aisoc_cases.alert_ids` — the denormalised list the console renders
--
-- `POST /cases/from-correlation` used to append every eligible alert to
-- `alert_ids` *before* claiming it, so an alert that already belonged to another
-- case stayed listed on the new case while `alerts.case_id` still pointed at the
-- owner. The workspace then showed "LINKED ALERTS (4)" while the investigation
-- brief — which reads `alerts.case_id` — correctly said "0 linked alert(s)".
-- `POST /cases/{id}/alerts` had the mirror-image bug: it appended to the array
-- without claiming, so the brief never saw manually linked alerts.
--
-- This migration makes the two agree once, in the only order that cannot lose a
-- link, and the writers keep them in step from now on.
--
-- 1. Claim what a case already lists (manual adds, historic correlation rows).
-- 2. Drop array entries whose alert is owned by a *different* case.
-- 3. Append alerts owned by the case but missing from its array.
--
-- Idempotent: re-running it is a no-op.

BEGIN;

-- 1. Claim: an alert listed on a case and owned by nobody belongs to that case.
UPDATE alerts a
   SET case_id = c.id,
       updated_at = now()
  FROM aisoc_cases c
 WHERE a.id = ANY (c.alert_ids)
   AND a.case_id IS NULL;

-- 2. Trim: an alert owned by another case is not evidence for this one.
UPDATE aisoc_cases c
   SET alert_ids = COALESCE(
         (
           SELECT array_agg(DISTINCT a.id)
             FROM alerts a
            WHERE a.id = ANY (c.alert_ids)
              AND a.case_id = c.id
         ),
         ARRAY[]::uuid[]
       ),
       updated_at = now()
 WHERE c.alert_ids IS NOT NULL
   AND cardinality(c.alert_ids) > 0
   AND EXISTS (
         SELECT 1
           FROM alerts a
          WHERE a.id = ANY (c.alert_ids)
            AND a.case_id IS DISTINCT FROM c.id
       );

-- 3. Append: an alert owned by the case must appear in its list.
UPDATE aisoc_cases c
   SET alert_ids = COALESCE(c.alert_ids, ARRAY[]::uuid[]) || missing.ids,
       updated_at = now()
  FROM (
        SELECT a.case_id AS case_id, array_agg(a.id) AS ids
          FROM alerts a
          JOIN aisoc_cases c2 ON c2.id = a.case_id
         WHERE NOT (a.id = ANY (COALESCE(c2.alert_ids, ARRAY[]::uuid[])))
         GROUP BY a.case_id
       ) AS missing
 WHERE c.id = missing.case_id;

COMMIT;
