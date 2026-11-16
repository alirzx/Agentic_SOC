-- 075_shift_month_schedules.sql
-- Monthly SOC roster (day/night) with generate + manual edit support.

BEGIN;

CREATE TABLE IF NOT EXISTS shift_month_schedules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    year          INTEGER NOT NULL,
    month         INTEGER NOT NULL CHECK (month BETWEEN 1 AND 12),
    assignments   JSONB NOT NULL DEFAULT '[]'::jsonb,
    analysts      JSONB NOT NULL DEFAULT '[]'::jsonb,
    stats         JSONB NOT NULL DEFAULT '{}'::jsonb,
    generated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT,
    CONSTRAINT uq_shift_month_tenant UNIQUE (tenant_id, year, month)
);

CREATE INDEX IF NOT EXISTS ix_shift_month_tenant_ym
  ON shift_month_schedules (tenant_id, year DESC, month DESC);

COMMENT ON TABLE shift_month_schedules IS
  'One saved day/night roster per tenant-month; regenerate overwrites assignments.';

COMMIT;
