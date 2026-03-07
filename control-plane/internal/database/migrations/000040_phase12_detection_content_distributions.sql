CREATE TABLE IF NOT EXISTS detection_content_distributions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    rulepack_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    rollout_channel TEXT NOT NULL DEFAULT 'canary',
    status TEXT NOT NULL DEFAULT 'queued',
    artifact_ref TEXT NOT NULL DEFAULT '',
    signature_ref TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    delivered_by TEXT NOT NULL DEFAULT '',
    delivered_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT detection_content_distributions_rulepack_fk
        FOREIGN KEY (rulepack_id)
        REFERENCES detection_rulepacks (id)
        ON DELETE CASCADE,
    CONSTRAINT detection_content_distributions_version_fk
        FOREIGN KEY (version_id)
        REFERENCES detection_rulepack_versions (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS detection_content_distributions_tenant_updated_idx
    ON detection_content_distributions (tenant_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS detection_content_distributions_tenant_rulepack_idx
    ON detection_content_distributions (tenant_id, rulepack_id, version_id, updated_at DESC);
