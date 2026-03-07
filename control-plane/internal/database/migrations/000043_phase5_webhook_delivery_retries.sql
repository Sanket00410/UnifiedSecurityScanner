ALTER TABLE webhook_deliveries
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 1;

ALTER TABLE webhook_deliveries
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NULL;

ALTER TABLE webhook_deliveries
    ADD COLUMN IF NOT EXISTS dead_lettered_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS webhook_deliveries_retry_schedule_idx
    ON webhook_deliveries (tenant_id, status, next_attempt_at)
    WHERE status = 'scheduled_retry';

CREATE INDEX IF NOT EXISTS webhook_deliveries_latest_attempt_idx
    ON webhook_deliveries (tenant_id, webhook_id, platform_event_id, attempted_at DESC, id DESC);
