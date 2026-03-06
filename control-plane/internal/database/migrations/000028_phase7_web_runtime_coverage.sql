CREATE TABLE IF NOT EXISTS web_runtime_coverage_runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    web_target_id TEXT NOT NULL REFERENCES web_targets(id) ON DELETE CASCADE,
    scan_job_id TEXT NOT NULL DEFAULT '',
    route_coverage DOUBLE PRECISION NOT NULL DEFAULT 0,
    api_coverage DOUBLE PRECISION NOT NULL DEFAULT 0,
    auth_coverage DOUBLE PRECISION NOT NULL DEFAULT 0,
    discovered_route_count BIGINT NOT NULL DEFAULT 0,
    discovered_api_operation_count BIGINT NOT NULL DEFAULT 0,
    discovered_auth_state_count BIGINT NOT NULL DEFAULT 0,
    evidence_ref TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS web_runtime_coverage_runs_tenant_target_created_idx
    ON web_runtime_coverage_runs (tenant_id, web_target_id, created_at DESC);

CREATE INDEX IF NOT EXISTS web_runtime_coverage_runs_scan_job_idx
    ON web_runtime_coverage_runs (scan_job_id);
