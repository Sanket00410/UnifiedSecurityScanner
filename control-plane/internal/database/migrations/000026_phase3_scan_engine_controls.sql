CREATE TABLE IF NOT EXISTS scan_engine_controls (
    tenant_id TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    target_kind TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rulepack_version TEXT NOT NULL DEFAULT '',
    max_runtime_seconds BIGINT NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, adapter_id, target_kind)
);

CREATE INDEX IF NOT EXISTS idx_scan_engine_controls_tenant_updated
    ON scan_engine_controls (tenant_id, updated_at DESC);
