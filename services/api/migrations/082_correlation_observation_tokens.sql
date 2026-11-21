-- 079_correlation_observation_tokens.sql
--
-- Persist the correlation engine's weighted keys on the observation ledger.
--
-- `services/correlation` scores pairs from `Observation.tokens`
-- (`{k.token for k in keys if k.weight > 0}`), where a token is
-- `kind:value` — or `kind:scope|value` for host-scoped process GUIDs. The
-- ledger only stored the entity buckets, so anything reconstructing scores
-- from Postgres (the candidate list in `services/api`) could not see `hash`,
-- `process_guid` or zero-weight filtering and had to approximate L3 from
-- hosts/users/ips/domains alone.
--
-- Storing the token set verbatim makes the API's L3 identical to the engine's:
-- same tokens, same 3-hop rule, same input.
--
-- Rows written before this migration have `'[]'` and fall back to the
-- entity-derived tokens until the engine re-normalises them (upsert on
-- `(tenant_id, observation_key)` rewrites the column on the next cycle).

BEGIN;

ALTER TABLE correlation_observations
    ADD COLUMN IF NOT EXISTS tokens JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN correlation_observations.tokens IS
    'Weighted correlation keys from extract_keys() as `kind:value` (or '
    '`kind:scope|value` for host-scoped process GUIDs), weight > 0 only. '
    'Source of truth for L3 graph proximity when scoring is rebuilt offline.';

COMMIT;
