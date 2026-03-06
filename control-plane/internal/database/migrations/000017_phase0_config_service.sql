CREATE TABLE IF NOT EXISTS tenant_config (
    tenant_id TEXT NOT NULL,
    config_key TEXT NOT NULL,
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, config_key)
);

CREATE INDEX IF NOT EXISTS tenant_config_tenant_updated_idx
    ON tenant_config (tenant_id, updated_at DESC);
