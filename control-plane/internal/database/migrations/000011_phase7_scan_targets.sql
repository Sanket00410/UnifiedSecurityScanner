CREATE TABLE IF NOT EXISTS scan_targets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    tools TEXT[] NOT NULL DEFAULT '{}'::text[],
    labels_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT '',
    last_run_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS scan_targets_tenant_updated_idx
    ON scan_targets (tenant_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS scan_targets_tenant_target_kind_idx
    ON scan_targets (tenant_id, target_kind);
