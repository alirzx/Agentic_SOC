-- 074_correlation_engine.sql
--
-- Backing store for the v2.0 graph correlation engine
-- (docs/plans/case/2.0.md). Three concerns, deliberately separated:
--
--   1. Alert ownership      — the atomic `correlation_owner` lock that lets the
--                             new engine and the legacy promoter run in
--                             parallel without ever putting one alert in two
--                             cases (doc §7.1).
--   2. Frequency baseline   — `value_frequency` powers the "is this value rare
--                             for *this* tenant?" weighting (doc §5.1).
--   3. Observation audit    — `correlation_observations` is the durable record
--                             of what the engine grouped; Neo4j is the query
--                             surface, Postgres is the ledger.
--
-- It also unifies `case_id` on the two tables that still stored it as text.
-- Every existing value is already a UUID (verified against the dev stack on
-- 2026-11-09), and the conversion is guarded so a non-UUID value can never make
-- the migration destroy data — it skips and raises a notice instead.

BEGIN;

-- ── 1. Alert ownership + correlation bookkeeping ──────────────────────────
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS correlation_owner TEXT,
    ADD COLUMN IF NOT EXISTS correlation_claimed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS correlation_state TEXT,
    ADD COLUMN IF NOT EXISTS normalizer_version TEXT;

COMMENT ON COLUMN alerts.correlation_owner IS
    'Which engine owns this alert: legacy | graph_engine. NULL = unclaimed.';
COMMENT ON COLUMN alerts.correlation_state IS
    'Engine outcome: claimed | cased | no_case | error | deduplicated_into_case.';
COMMENT ON COLUMN alerts.normalizer_version IS
    'extract_keys() version used when this alert was last normalised.';

-- Worker scan: "unclaimed, uncased alerts for this tenant, oldest first".
CREATE INDEX IF NOT EXISTS ix_alerts_correlation_pending
    ON alerts (tenant_id, created_at)
    WHERE correlation_owner IS NULL AND case_id IS NULL;

CREATE INDEX IF NOT EXISTS ix_alerts_correlation_owner
    ON alerts (tenant_id, correlation_owner, correlation_claimed_at);

-- ── 2. Frequency baseline (doc §5.1) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS value_frequency (
    tenant_id    UUID        NOT NULL,
    kind         TEXT        NOT NULL,
    value        TEXT        NOT NULL,
    freq_30d     INTEGER     NOT NULL DEFAULT 0,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, kind, value)
);

CREATE INDEX IF NOT EXISTS ix_value_frequency_freq
    ON value_frequency (tenant_id, kind, freq_30d DESC);

COMMENT ON TABLE value_frequency IS
    'Per-tenant 30-day value frequency used to weight correlation keys. Never cross-tenant.';

-- ── 3. Observation ledger (doc §4.2 / §6) ────────────────────────────────
CREATE TABLE IF NOT EXISTS correlation_observations (
    tenant_id          UUID        NOT NULL,
    observation_key    TEXT        NOT NULL,
    alert_ids          UUID[]      NOT NULL DEFAULT ARRAY[]::UUID[],
    role               TEXT,
    techniques         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    hosts              JSONB       NOT NULL DEFAULT '[]'::jsonb,
    users              JSONB       NOT NULL DEFAULT '[]'::jsonb,
    ips                JSONB       NOT NULL DEFAULT '[]'::jsonb,
    domains            JSONB       NOT NULL DEFAULT '[]'::jsonb,
    first_seen         TIMESTAMPTZ,
    last_seen          TIMESTAMPTZ,
    time_quality       TEXT,
    normalizer_version TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, observation_key)
);

CREATE INDEX IF NOT EXISTS ix_correlation_observations_alerts
    ON correlation_observations USING GIN (alert_ids);

COMMENT ON TABLE correlation_observations IS
    'Durable record of graph-based dedup output: one row per atomic attacker action.';

-- ── 4. Per-tenant role overrides (doc §5.2) ──────────────────────────────
CREATE TABLE IF NOT EXISTS correlation_rule_roles (
    tenant_id  UUID        NOT NULL,
    rule_name  TEXT        NOT NULL,
    role       TEXT        NOT NULL,
    note       TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, rule_name)
);

COMMENT ON TABLE correlation_rule_roles IS
    'Operator overrides for alert→role assignment. Empty table = built-in map only.';

-- ── 5. case_id type unification (doc §2, §7.2) ───────────────────────────
-- `alerts.case_id` is already UUID. `investigation_runs.case_id` and
-- `agent_approvals.case_id` were VARCHAR(200) holding UUID strings, which made
-- joins against `aisoc_cases` fail silently. Convert only when every row is a
-- valid UUID; otherwise leave the column alone and surface a notice.
DO $$
DECLARE
    bad_runs   BIGINT;
    bad_apprs  BIGINT;
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'investigation_runs'
           AND column_name = 'case_id'
           AND data_type = 'character varying'
    ) THEN
        SELECT COUNT(*) INTO bad_runs
          FROM investigation_runs
         WHERE case_id IS NOT NULL
           AND case_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
        IF bad_runs = 0 THEN
            ALTER TABLE investigation_runs
                ALTER COLUMN case_id TYPE UUID USING case_id::uuid;
            RAISE NOTICE 'investigation_runs.case_id converted to UUID';
        ELSE
            RAISE NOTICE 'investigation_runs.case_id NOT converted: % non-UUID value(s)', bad_runs;
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'agent_approvals'
           AND column_name = 'case_id'
           AND data_type = 'character varying'
    ) THEN
        SELECT COUNT(*) INTO bad_apprs
          FROM agent_approvals
         WHERE case_id IS NOT NULL
           AND case_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
        IF bad_apprs = 0 THEN
            ALTER TABLE agent_approvals
                ALTER COLUMN case_id TYPE UUID USING case_id::uuid;
            RAISE NOTICE 'agent_approvals.case_id converted to UUID';
        ELSE
            RAISE NOTICE 'agent_approvals.case_id NOT converted: % non-UUID value(s)', bad_apprs;
        END IF;
    END IF;
END $$;

COMMIT;
