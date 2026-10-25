-- 061_alerts_llm_payload.sql
--
-- The optimized Splunk notable pipeline emits a curated `llm_payload` per
-- notable (rule.title/title_template/description/spl/macro_definitions,
-- alert_fields, event_time + event_time_source, date_context, risk context,
-- annotations). Until now it only existed inside `alerts.raw_event` →
-- `raw_data` (canonical envelope JSON) → `raw_event` (the Splunk row), so every
-- consumer had to unwrap three nesting levels to reach the model evidence —
-- and the Agents' `extract_llm_payload` resolver existed only to do that walk.
--
-- Migration 061 promotes it to a first-class column that fusion writes at
-- promote time (services/fusion/app/services/alert_sink.py), the API serves on
-- the alert detail (AlertDetailResponse.llm_payload) and maps into
-- `raw_alert.llm_payload` for the agents
-- (services/api/app/api/v1/endpoints/agents.py:_build_raw_alert), so the prompt
-- evidence is read directly instead of reconstructed.
--
-- Nullable on purpose: connectors without a notable pipeline (everything except
-- Splunk) have no payload, and legacy rows predate the column.
--
-- Idempotent ADD COLUMN so create_all / 001_init / incremental lineages all
-- converge (same pattern as 052 and 057).

BEGIN;

ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS llm_payload JSONB;

COMMENT ON COLUMN alerts.llm_payload IS
  'Curated LLM evidence payload emitted by the connector query (Splunk notable pipeline); NULL for connectors without one.';

COMMIT;
