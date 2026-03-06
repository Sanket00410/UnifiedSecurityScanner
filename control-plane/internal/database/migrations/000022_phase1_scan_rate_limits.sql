ALTER TABLE tenant_limits
    ADD COLUMN IF NOT EXISTS max_scan_jobs_per_minute BIGINT NOT NULL DEFAULT 0;
