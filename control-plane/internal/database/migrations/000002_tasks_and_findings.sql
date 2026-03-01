ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS running_task_count INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS scan_job_tasks (
    id TEXT PRIMARY KEY,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs (id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    assigned_worker_id TEXT,
    lease_id TEXT,
    approved_modules TEXT[] NOT NULL DEFAULT '{}'::text[],
    labels_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    max_runtime_seconds BIGINT NOT NULL,
    evidence_upload_url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    assigned_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS scan_job_tasks_status_adapter_idx
    ON scan_job_tasks (status, adapter_id, created_at);

CREATE TABLE IF NOT EXISTS normalized_findings (
    finding_id TEXT PRIMARY KEY,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs (id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES scan_job_tasks (id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    finding_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
