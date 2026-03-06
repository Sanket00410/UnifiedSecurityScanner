CREATE TABLE IF NOT EXISTS platform_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    source_service TEXT NOT NULL DEFAULT '',
    aggregate_type TEXT NOT NULL DEFAULT '',
    aggregate_id TEXT NOT NULL DEFAULT '',
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS platform_events_tenant_created_idx
    ON platform_events (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS platform_events_type_created_idx
    ON platform_events (event_type, created_at DESC);

CREATE TABLE IF NOT EXISTS tenant_limits (
    tenant_id TEXT PRIMARY KEY,
    max_total_scan_jobs BIGINT NOT NULL DEFAULT 0,
    max_active_scan_jobs BIGINT NOT NULL DEFAULT 0,
    max_scan_targets BIGINT NOT NULL DEFAULT 0,
    max_ingestion_sources BIGINT NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS tenant_limits_updated_idx
    ON tenant_limits (updated_at DESC);
