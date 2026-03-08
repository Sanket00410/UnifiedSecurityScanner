CREATE TABLE IF NOT EXISTS ps_connectors (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    connector_kind TEXT NOT NULL,
    endpoint_url TEXT NOT NULL DEFAULT '',
    auth_type TEXT NOT NULL DEFAULT 'none',
    auth_secret_ref TEXT NOT NULL DEFAULT '',
    default_headers_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    retry_max_attempts INTEGER NOT NULL DEFAULT 5,
    retry_base_delay_seconds INTEGER NOT NULL DEFAULT 5,
    retry_max_delay_seconds INTEGER NOT NULL DEFAULT 300,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ps_connectors_name_unique UNIQUE (tenant_id, name),
    CONSTRAINT ps_connectors_retry_max_attempts_check CHECK (retry_max_attempts BETWEEN 1 AND 10),
    CONSTRAINT ps_connectors_retry_base_delay_check CHECK (retry_base_delay_seconds BETWEEN 1 AND 3600),
    CONSTRAINT ps_connectors_retry_max_delay_check CHECK (retry_max_delay_seconds BETWEEN 1 AND 86400),
    CONSTRAINT ps_connectors_retry_delay_order_check CHECK (retry_max_delay_seconds >= retry_base_delay_seconds)
);

CREATE INDEX IF NOT EXISTS ps_connectors_tenant_kind_idx
    ON ps_connectors (tenant_id, connector_kind, updated_at DESC);

CREATE TABLE IF NOT EXISTS ps_platform_jobs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    job_kind TEXT NOT NULL,
    connector_id TEXT NULL REFERENCES ps_connectors (id) ON DELETE SET NULL,
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'queued',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    last_error TEXT NOT NULL DEFAULT '',
    last_response_status INTEGER NOT NULL DEFAULT 0,
    last_response_body TEXT NOT NULL DEFAULT '',
    leased_by TEXT NOT NULL DEFAULT '',
    lease_expires_at TIMESTAMPTZ NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS ps_platform_jobs_queue_idx
    ON ps_platform_jobs (status, next_attempt_at, lease_expires_at);

CREATE INDEX IF NOT EXISTS ps_platform_jobs_tenant_idx
    ON ps_platform_jobs (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ps_platform_job_attempts (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES ps_platform_jobs (id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    connector_id TEXT NULL,
    worker_id TEXT NOT NULL DEFAULT '',
    success BOOLEAN NOT NULL DEFAULT FALSE,
    response_status INTEGER NOT NULL DEFAULT 0,
    response_body TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    duration_ms BIGINT NOT NULL DEFAULT 0,
    attempted_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ps_platform_job_attempts_job_idx
    ON ps_platform_job_attempts (job_id, attempted_at DESC);

CREATE TABLE IF NOT EXISTS ps_notifications (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    owner_team TEXT NOT NULL DEFAULT '',
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    acknowledged_at TIMESTAMPTZ NULL,
    acknowledged_by TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS ps_notifications_tenant_status_idx
    ON ps_notifications (tenant_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS ps_audit_exports (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'jsonl',
    destination_ref TEXT NOT NULL DEFAULT '',
    filters_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'queued',
    requested_by TEXT NOT NULL DEFAULT '',
    requested_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NULL,
    file_ref TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS ps_audit_exports_tenant_status_idx
    ON ps_audit_exports (tenant_id, status, requested_at DESC);

CREATE TABLE IF NOT EXISTS ps_sync_runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    sync_kind TEXT NOT NULL,
    source_ref TEXT NOT NULL DEFAULT '',
    version_tag TEXT NOT NULL DEFAULT '',
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'queued',
    started_by TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NULL,
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS ps_sync_runs_tenant_kind_status_idx
    ON ps_sync_runs (tenant_id, sync_kind, status, started_at DESC);
