CREATE TABLE IF NOT EXISTS runtime_telemetry_connectors (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_sync_at TIMESTAMPTZ NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS runtime_telemetry_connectors_tenant_type_updated_idx
    ON runtime_telemetry_connectors (tenant_id, connector_type, updated_at DESC);

CREATE TABLE IF NOT EXISTS runtime_telemetry_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    connector_id TEXT NOT NULL DEFAULT '',
    source_kind TEXT NOT NULL DEFAULT '',
    source_ref TEXT NOT NULL DEFAULT '',
    asset_id TEXT NOT NULL DEFAULT '',
    finding_id TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    observed_at TIMESTAMPTZ NOT NULL,
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS runtime_telemetry_events_tenant_observed_idx
    ON runtime_telemetry_events (tenant_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS runtime_telemetry_events_tenant_event_type_idx
    ON runtime_telemetry_events (tenant_id, event_type, observed_at DESC);

CREATE INDEX IF NOT EXISTS runtime_telemetry_events_tenant_connector_idx
    ON runtime_telemetry_events (tenant_id, connector_id, observed_at DESC);
