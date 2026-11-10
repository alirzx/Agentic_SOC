-- 068_playbook_runs_dedupe.sql
--
-- Automation rules re-evaluate a subject on every alert update, so a rule with a
-- linked playbook would otherwise fire that playbook once per update. The
-- control-plane API therefore stamps each start with a stable key
-- (``automation:<rule>:<playbook>:<subject>``) that is stored in the run's
-- ``trigger_context`` and checked before a second run is created
-- (``run_store.find_run_by_dedupe``).
--
-- That lookup filters on ``trigger_context->>'dedupe_key'``. Without an index on
-- the expression it degrades into a sequential scan of ``playbook_runs`` — the
-- table that grows fastest in a busy tenant — so index the expression directly.
--
-- The index is deliberately *not* unique: the API's ledger ``idempotency_key``
-- (unique per tenant) is the authoritative at-most-once guarantee, and a unique
-- constraint here could not be honoured anyway — ``persist_run`` swallows
-- constraint violations as best-effort failures, which would let a run execute
-- unpersisted instead of refusing to start.
--
-- Idempotent: safe to re-run.

CREATE INDEX IF NOT EXISTS idx_playbook_runs_dedupe
    ON playbook_runs (
        tenant_id,
        playbook_id,
        ((trigger_context->>'dedupe_key'))
    )
    WHERE trigger_context->>'dedupe_key' IS NOT NULL;

COMMENT ON INDEX idx_playbook_runs_dedupe IS
    'Lookup for an existing run started under a caller-supplied dedupe key (automation rules).';

-- ============================================================
-- 2. automation_rules columns the executor reads
-- ============================================================
-- ``rule_executor._FETCH_RULES`` selects ``playbook_ref`` and filters on
-- ``subject_type`` on the alert write path. Both columns were previously added
-- only at runtime by ``_ensure_rule_extra_columns()``, which is invoked from the
-- rules endpoints and cached per process — so a fresh deployment that saw an
-- alert before anyone opened the Automation Rules page failed the whole rule
-- query and silently evaluated nothing. Same types and defaults as that helper.

ALTER TABLE automation_rules
    ADD COLUMN IF NOT EXISTS subject_type VARCHAR(32) DEFAULT 'alert';

ALTER TABLE automation_rules
    ADD COLUMN IF NOT EXISTS playbook_ref TEXT;

COMMENT ON COLUMN automation_rules.playbook_ref IS
    'Playbook started when this rule matches and governance allows its action.';
