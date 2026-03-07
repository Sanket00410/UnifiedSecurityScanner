CREATE TABLE IF NOT EXISTS webhook_integrations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    endpoint_url TEXT NOT NULL,
    event_types_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    headers_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    secret_encrypted TEXT NOT NULL DEFAULT '',
    last_attempt_at TIMESTAMPTZ NULL,
    last_success_at TIMESTAMPTZ NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS webhook_integrations_tenant_status_updated_idx
    ON webhook_integrations (tenant_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    webhook_id TEXT NOT NULL,
    platform_event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'failed',
    response_status INTEGER NOT NULL DEFAULT 0,
    response_body TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    attempted_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT webhook_deliveries_webhook_fk
        FOREIGN KEY (webhook_id)
        REFERENCES webhook_integrations (id)
        ON DELETE CASCADE,
    CONSTRAINT webhook_deliveries_event_fk
        FOREIGN KEY (platform_event_id)
        REFERENCES platform_events (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS webhook_deliveries_tenant_webhook_attempted_idx
    ON webhook_deliveries (tenant_id, webhook_id, attempted_at DESC);

CREATE INDEX IF NOT EXISTS webhook_deliveries_tenant_status_attempted_idx
    ON webhook_deliveries (tenant_id, status, attempted_at DESC);
