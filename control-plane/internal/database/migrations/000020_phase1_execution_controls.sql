CREATE TABLE IF NOT EXISTS tenant_execution_controls (
    tenant_id TEXT PRIMARY KEY,
    emergency_stop_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    emergency_stop_reason TEXT NOT NULL DEFAULT '',
    maintenance_windows_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tenant_execution_controls_emergency_stop
    ON tenant_execution_controls (emergency_stop_enabled, updated_at DESC);
