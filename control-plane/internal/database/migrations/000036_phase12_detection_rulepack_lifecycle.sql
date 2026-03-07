CREATE TABLE IF NOT EXISTS detection_rulepacks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    engine TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    description TEXT NOT NULL DEFAULT '',
    current_version TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS detection_rulepacks_tenant_engine_updated_idx
    ON detection_rulepacks (tenant_id, engine, updated_at DESC);

CREATE TABLE IF NOT EXISTS detection_rulepack_versions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    rulepack_id TEXT NOT NULL,
    version_tag TEXT NOT NULL,
    content_ref TEXT NOT NULL DEFAULT '',
    checksum TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft',
    quality_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    published_by TEXT NOT NULL DEFAULT '',
    published_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, rulepack_id, version_tag),
    CONSTRAINT detection_rulepack_versions_rulepack_fk
        FOREIGN KEY (rulepack_id)
        REFERENCES detection_rulepacks (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS detection_rulepack_versions_tenant_rulepack_status_idx
    ON detection_rulepack_versions (tenant_id, rulepack_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS detection_rulepack_rollouts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    rulepack_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT 'canary',
    status TEXT NOT NULL DEFAULT 'started',
    target_scope TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    started_by TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT detection_rulepack_rollouts_rulepack_fk
        FOREIGN KEY (rulepack_id)
        REFERENCES detection_rulepacks (id)
        ON DELETE CASCADE,
    CONSTRAINT detection_rulepack_rollouts_version_fk
        FOREIGN KEY (version_id)
        REFERENCES detection_rulepack_versions (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS detection_rulepack_rollouts_tenant_rulepack_started_idx
    ON detection_rulepack_rollouts (tenant_id, rulepack_id, started_at DESC);
