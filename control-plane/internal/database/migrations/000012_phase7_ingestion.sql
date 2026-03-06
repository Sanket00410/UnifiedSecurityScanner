CREATE TABLE IF NOT EXISTS ingestion_sources (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    target_kind TEXT NOT NULL,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    tools TEXT[] NOT NULL DEFAULT '{}'::text[],
    labels_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_hash TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    last_event_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS ingestion_sources_tenant_updated_idx
    ON ingestion_sources (tenant_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS ingestion_sources_tenant_provider_idx
    ON ingestion_sources (tenant_id, provider, enabled);

CREATE TABLE IF NOT EXISTS ingestion_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    external_id TEXT NOT NULL DEFAULT '',
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL,
    error_message TEXT NOT NULL DEFAULT '',
    created_scan_job_id TEXT NOT NULL DEFAULT '',
    policy_id TEXT NOT NULL DEFAULT '',
    policy_rule_hits_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ingestion_events_tenant_created_idx
    ON ingestion_events (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ingestion_events_source_created_idx
    ON ingestion_events (source_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS ingestion_events_source_external_unique_idx
    ON ingestion_events (tenant_id, source_id, external_id)
    WHERE external_id <> '';
