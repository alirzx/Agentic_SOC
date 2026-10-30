-- 070_automation_rules_metadata.sql
--
-- Move the last of the automation_rules columns out of request-time DDL and
-- into the schema.
--
-- `GET /runbook/automation-rules` used to run `ALTER TABLE automation_rules
-- ADD COLUMN IF NOT EXISTS …` on first call per process
-- (`_ensure_rule_extra_columns`). Three problems with that:
--
--   1. A read-only endpoint needed ALTER privileges, so a least-privilege API
--      role could not list its own rules.
--   2. The helper ran only from the rules endpoints. `rule_executor._FETCH_RULES`
--      (the alert write path) and the draft-preview endpoint read the same
--      columns without calling it, so on a freshly migrated database they failed
--      until somebody opened the Automation Rules page.
--   3. Schema changes are not something a request should be able to perform.
--
-- Columns added here are the ones `_LIST_RULES` / `_GET_RULE` select:
--
--   * `docs_ref`    — operator documentation link shown on the rule.
--   * `owner_team`  — team accountable for the rule.
--   * `success_count` / `failed_count` / `denied_count` — reserved outcome
--     counters. Nothing increments them yet; the API returns 0 and the UI only
--     renders the badges when a value is non-zero, so their absence of a writer
--     is not currently presented as activity.
--
-- Idempotent: safe to re-run.

ALTER TABLE automation_rules
    ADD COLUMN IF NOT EXISTS docs_ref TEXT;

ALTER TABLE automation_rules
    ADD COLUMN IF NOT EXISTS owner_team VARCHAR(128);

ALTER TABLE automation_rules
    ADD COLUMN IF NOT EXISTS success_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE automation_rules
    ADD COLUMN IF NOT EXISTS failed_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE automation_rules
    ADD COLUMN IF NOT EXISTS denied_count INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN automation_rules.docs_ref IS
    'Optional link to the runbook/operator documentation for this rule.';

COMMENT ON COLUMN automation_rules.owner_team IS
    'Team accountable for keeping this rule correct.';

COMMENT ON COLUMN automation_rules.success_count IS
    'Reserved outcome counter. No writer yet — do not present a zero as measured reliability.';
