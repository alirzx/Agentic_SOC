-- 077_phase2_dismissals_and_attachments.sql
--
-- Phase 2: Candidate Dismissals and Alert Attachment Tracking
--
-- This migration adds:
--   1. CaseCandidateDismissal table — tracks when analyst dismisses a candidate (snooze for 24h)
--   2. Alert.attached_via column — tracks how an alert was attached to a case
--      - 'engine': Automatically attached by correlation engine
--      - 'suggestion': Attached via suggestions panel
--      - 'manual': Manually attached by analyst
--      - 'graph_correlation_manual': Attached from graph view
--
-- Date: 2026-11-09

BEGIN;

-- ── 1. Create case_candidate_dismissals table ─────────────────────────────
CREATE TABLE IF NOT EXISTS case_candidate_dismissals (
    id            UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id     UUID        NOT NULL,
    candidate_key VARCHAR(255) NOT NULL,
    dismissed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, candidate_key),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_dismissals_tenant 
    ON case_candidate_dismissals (tenant_id);

CREATE INDEX IF NOT EXISTS ix_dismissals_candidate_key 
    ON case_candidate_dismissals (candidate_key);

CREATE INDEX IF NOT EXISTS ix_dismissals_dismissed_at 
    ON case_candidate_dismissals (dismissed_at);

COMMENT ON TABLE case_candidate_dismissals IS
    'Tracks when analyst dismisses a candidate (snooze for 24h).';

COMMENT ON COLUMN case_candidate_dismissals.candidate_key IS
    'Unique key for the dismissed candidate (e.g., hash of case seed + related alerts).';

COMMENT ON COLUMN case_candidate_dismissals.dismissed_at IS
    'When the candidate was dismissed. Snoozed for 24 hours from this time.';


-- ── 2. Add attached_via column to alerts table ────────────────────────────
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS attached_via VARCHAR(50);

COMMENT ON COLUMN alerts.attached_via IS
    'How alert was attached to case: engine | suggestion | manual | graph_correlation_manual';

CREATE INDEX IF NOT EXISTS ix_alerts_attached_via 
    ON alerts (attached_via);


COMMIT;
