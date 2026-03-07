ALTER TABLE webhook_integrations
    ADD COLUMN IF NOT EXISTS retry_max_attempts INTEGER NOT NULL DEFAULT 3;

ALTER TABLE webhook_integrations
    ADD COLUMN IF NOT EXISTS retry_base_delay_seconds INTEGER NOT NULL DEFAULT 1;

ALTER TABLE webhook_integrations
    ADD COLUMN IF NOT EXISTS retry_max_delay_seconds INTEGER NOT NULL DEFAULT 30;

ALTER TABLE webhook_integrations
    DROP CONSTRAINT IF EXISTS webhook_integrations_retry_max_attempts_check;

ALTER TABLE webhook_integrations
    ADD CONSTRAINT webhook_integrations_retry_max_attempts_check
    CHECK (retry_max_attempts BETWEEN 1 AND 10);

ALTER TABLE webhook_integrations
    DROP CONSTRAINT IF EXISTS webhook_integrations_retry_base_delay_seconds_check;

ALTER TABLE webhook_integrations
    ADD CONSTRAINT webhook_integrations_retry_base_delay_seconds_check
    CHECK (retry_base_delay_seconds BETWEEN 1 AND 3600);

ALTER TABLE webhook_integrations
    DROP CONSTRAINT IF EXISTS webhook_integrations_retry_max_delay_seconds_check;

ALTER TABLE webhook_integrations
    ADD CONSTRAINT webhook_integrations_retry_max_delay_seconds_check
    CHECK (retry_max_delay_seconds BETWEEN 1 AND 86400);

ALTER TABLE webhook_integrations
    DROP CONSTRAINT IF EXISTS webhook_integrations_retry_delay_order_check;

ALTER TABLE webhook_integrations
    ADD CONSTRAINT webhook_integrations_retry_delay_order_check
    CHECK (retry_max_delay_seconds >= retry_base_delay_seconds);
