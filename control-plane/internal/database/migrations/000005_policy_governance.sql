ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS version_number BIGINT NOT NULL DEFAULT 1;

ALTER TABLE scan_job_tasks
    ADD COLUMN IF NOT EXISTS policy_status TEXT NOT NULL DEFAULT 'approved';

ALTER TABLE scan_job_tasks
    ADD COLUMN IF NOT EXISTS policy_reason TEXT NOT NULL DEFAULT '';

ALTER TABLE scan_job_tasks
    ADD COLUMN IF NOT EXISTS policy_rule_hits_json JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS scan_job_tasks_policy_status_idx
    ON scan_job_tasks (status, policy_status, adapter_id, created_at);

CREATE TABLE IF NOT EXISTS policy_versions (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL REFERENCES policies (id) ON DELETE CASCADE,
    version_number BIGINT NOT NULL,
    change_type TEXT NOT NULL,
    snapshot_json JSONB NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (policy_id, version_number)
);

CREATE INDEX IF NOT EXISTS policy_versions_policy_created_idx
    ON policy_versions (policy_id, created_at DESC);

CREATE TABLE IF NOT EXISTS policy_approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs (id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES scan_job_tasks (id) ON DELETE CASCADE,
    policy_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    decided_by TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ NULL,
    UNIQUE (task_id)
);

CREATE INDEX IF NOT EXISTS policy_approvals_tenant_status_created_idx
    ON policy_approvals (tenant_id, status, created_at DESC);
