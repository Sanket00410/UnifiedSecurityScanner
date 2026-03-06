CREATE TABLE IF NOT EXISTS evidence_objects (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs (id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES scan_job_tasks (id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL DEFAULT '',
    object_key TEXT NOT NULL DEFAULT '',
    object_ref TEXT NOT NULL,
    storage_provider TEXT NOT NULL DEFAULT 'local',
    storage_tier TEXT NOT NULL DEFAULT 'hot',
    archived BOOLEAN NOT NULL DEFAULT FALSE,
    retention_until TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '',
    content_type TEXT NOT NULL DEFAULT '',
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, task_id, object_ref)
);

CREATE INDEX IF NOT EXISTS evidence_objects_tenant_created_idx
    ON evidence_objects (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS evidence_objects_tenant_task_idx
    ON evidence_objects (tenant_id, task_id, created_at DESC);

CREATE INDEX IF NOT EXISTS evidence_objects_tenant_job_idx
    ON evidence_objects (tenant_id, scan_job_id, created_at DESC);

CREATE INDEX IF NOT EXISTS evidence_objects_tenant_archived_retention_idx
    ON evidence_objects (tenant_id, archived, retention_until, updated_at DESC);

CREATE TABLE IF NOT EXISTS evidence_retention_runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    triggered_by TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    scanned_count BIGINT NOT NULL DEFAULT 0,
    archived_count BIGINT NOT NULL DEFAULT 0,
    deleted_count BIGINT NOT NULL DEFAULT 0,
    dry_run BOOLEAN NOT NULL DEFAULT FALSE,
    archive_before TIMESTAMPTZ NOT NULL,
    delete_archived_before TIMESTAMPTZ NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS evidence_retention_runs_tenant_started_idx
    ON evidence_retention_runs (tenant_id, started_at DESC);
