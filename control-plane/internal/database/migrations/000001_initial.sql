CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    tools TEXT[] NOT NULL,
    approval_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS scan_jobs_requested_at_idx
    ON scan_jobs (requested_at DESC);

CREATE TABLE IF NOT EXISTS workers (
    worker_id TEXT PRIMARY KEY,
    lease_id TEXT NOT NULL,
    worker_version TEXT NOT NULL,
    operating_system TEXT NOT NULL,
    hostname TEXT NOT NULL,
    capabilities_json JSONB NOT NULL,
    metrics_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    heartbeat_interval_seconds BIGINT NOT NULL,
    last_heartbeat_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
