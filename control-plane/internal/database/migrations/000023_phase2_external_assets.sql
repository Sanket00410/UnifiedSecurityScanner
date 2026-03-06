CREATE TABLE IF NOT EXISTS external_assets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, asset_type, value)
);

CREATE INDEX IF NOT EXISTS idx_external_assets_tenant_updated
    ON external_assets (tenant_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_external_assets_tenant_type_value
    ON external_assets (tenant_id, asset_type, value);
