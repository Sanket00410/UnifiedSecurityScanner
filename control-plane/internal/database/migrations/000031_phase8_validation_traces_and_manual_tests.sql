CREATE TABLE IF NOT EXISTS validation_attack_traces (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL REFERENCES validation_engagements(id) ON DELETE CASCADE,
    scan_job_id TEXT NOT NULL DEFAULT '',
    task_id TEXT NOT NULL DEFAULT '',
    adapter_id TEXT NOT NULL DEFAULT '',
    target_kind TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    evidence_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    artifacts_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    replay_manifest_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS validation_attack_traces_tenant_engagement_updated_idx
    ON validation_attack_traces (tenant_id, engagement_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS validation_attack_traces_tenant_scan_job_idx
    ON validation_attack_traces (tenant_id, scan_job_id);

CREATE TABLE IF NOT EXISTS validation_manual_test_cases (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL REFERENCES validation_engagements(id) ON DELETE CASCADE,
    wstg_id TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'not_started',
    assigned_to TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    evidence_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    completed_by TEXT NOT NULL DEFAULT '',
    completed_at TIMESTAMPTZ NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, engagement_id, wstg_id, title)
);

CREATE INDEX IF NOT EXISTS validation_manual_test_cases_tenant_engagement_updated_idx
    ON validation_manual_test_cases (tenant_id, engagement_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS validation_manual_test_cases_tenant_status_idx
    ON validation_manual_test_cases (tenant_id, status, updated_at DESC);
