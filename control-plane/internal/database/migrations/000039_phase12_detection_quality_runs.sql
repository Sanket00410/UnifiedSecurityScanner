CREATE TABLE IF NOT EXISTS detection_rulepack_quality_runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    rulepack_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    benchmark_name TEXT NOT NULL DEFAULT '',
    dataset_ref TEXT NOT NULL DEFAULT '',
    run_status TEXT NOT NULL DEFAULT 'failed',
    quality_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    total_tests BIGINT NOT NULL DEFAULT 0,
    passed_tests BIGINT NOT NULL DEFAULT 0,
    failed_tests BIGINT NOT NULL DEFAULT 0,
    false_positive_count BIGINT NOT NULL DEFAULT 0,
    false_negative_count BIGINT NOT NULL DEFAULT 0,
    regression_count BIGINT NOT NULL DEFAULT 0,
    suppression_delta BIGINT NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT '',
    executed_by TEXT NOT NULL DEFAULT '',
    executed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT detection_rulepack_quality_runs_rulepack_fk
        FOREIGN KEY (rulepack_id)
        REFERENCES detection_rulepacks (id)
        ON DELETE CASCADE,
    CONSTRAINT detection_rulepack_quality_runs_version_fk
        FOREIGN KEY (version_id)
        REFERENCES detection_rulepack_versions (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS detection_rulepack_quality_runs_tenant_rulepack_idx
    ON detection_rulepack_quality_runs (tenant_id, rulepack_id, executed_at DESC);

CREATE INDEX IF NOT EXISTS detection_rulepack_quality_runs_tenant_version_idx
    ON detection_rulepack_quality_runs (tenant_id, version_id, executed_at DESC);
