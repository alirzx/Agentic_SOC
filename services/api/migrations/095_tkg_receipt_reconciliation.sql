BEGIN;
ALTER TABLE tkg_alert_deliveries
    ADD COLUMN receipt_accepted_at timestamptz,
    ADD COLUMN reconcile_after timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN reconcile_fence bigint NOT NULL DEFAULT 0,
    ADD COLUMN reconcile_failures integer NOT NULL DEFAULT 0;
UPDATE tkg_alert_deliveries SET receipt_accepted_at=updated_at
    WHERE receipt_id IS NOT NULL;
CREATE INDEX tkg_pending_receipts_due ON tkg_alert_deliveries(reconcile_after, id)
    WHERE state='pending_materialization' AND receipt_id IS NOT NULL;
COMMIT;
