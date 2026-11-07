-- migrations/069_autonomy_action_enabled.sql
-- Add per-action enable/disable toggle to governance policy configuration.
--
-- Allows SOC managers to temporarily disable system-core actions at the
-- tenant level without deleting the policy config. Defaults to true (enabled).

ALTER TABLE aisoc_autonomy_thresholds
    ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN aisoc_autonomy_thresholds.enabled IS
    'Whether this action is currently enabled for the tenant. When false, the action will not execute even if thresholds are met.';
