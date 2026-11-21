-- 080_correlation_observation_scoring_inputs.sql
--
-- Persist the remaining inputs the engine uses to score a pair, so anything
-- rebuilding scores from the ledger (the candidate list in `services/api`) can
-- reproduce L1/L2 exactly instead of approximating them.
--
-- 079 stored the token *names* (`kind:value`). L1 is a weighted sum, so the
-- weights have to travel with them. L2 is not temporal proximity at all: it is
-- "same analytic story, next kill-chain step, or a different technique on a
-- shared entity" — which needs `stories` and `kill_chain`.
--
-- Rows written before this migration keep the defaults and are refreshed on the
-- engine's next upsert (`ON CONFLICT (tenant_id, observation_key)`).

BEGIN;

ALTER TABLE correlation_observations
    ADD COLUMN IF NOT EXISTS token_weights JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS stories JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS kill_chain JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN correlation_observations.token_weights IS
    'Map of correlation token -> weight (extract_keys weighting: strong=3, '
    'medium=2, weak=1). L1 = min(sum(shared weights), 18).';
COMMENT ON COLUMN correlation_observations.stories IS
    'Splunk analytic stories for the observation; L2 fires on a shared story.';
COMMENT ON COLUMN correlation_observations.kill_chain IS
    'Kill-chain phases (normalised names); L2 fires on a phase progression.';

COMMIT;
