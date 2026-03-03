ALTER TABLE normalized_findings
    ADD COLUMN IF NOT EXISTS finding_key TEXT;

ALTER TABLE normalized_findings
    ADD COLUMN IF NOT EXISTS occurrence_count BIGINT NOT NULL DEFAULT 1;

ALTER TABLE normalized_findings
    ADD COLUMN IF NOT EXISTS reopened_count BIGINT NOT NULL DEFAULT 0;

ALTER TABLE normalized_findings
    ADD COLUMN IF NOT EXISTS current_status TEXT NOT NULL DEFAULT 'open';

UPDATE normalized_findings
SET finding_key = md5(
    COALESCE(finding_json->'source'->>'tool', '') || '|' ||
    COALESCE(finding_json->>'category', '') || '|' ||
    COALESCE(finding_json->>'title', '') || '|' ||
    COALESCE(finding_json->'asset'->>'asset_id', '') || '|' ||
    COALESCE(finding_json->'asset'->>'asset_type', '') || '|' ||
    COALESCE(finding_json->'locations'->0->>'path', '') || '|' ||
    COALESCE(finding_json->'locations'->0->>'endpoint', '') || '|' ||
    COALESCE(finding_json->'locations'->0->>'line', '')
)
WHERE finding_key IS NULL
   OR finding_key = ''
   OR finding_key = finding_id;

ALTER TABLE normalized_findings
    ALTER COLUMN finding_key SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS normalized_findings_tenant_key_idx
    ON normalized_findings (tenant_id, finding_key);

CREATE INDEX IF NOT EXISTS normalized_findings_tenant_score_idx
    ON normalized_findings (tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS asset_profiles (
    tenant_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    asset_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    exposure TEXT NOT NULL,
    criticality DOUBLE PRECISION NOT NULL,
    owner_team TEXT NOT NULL DEFAULT '',
    tags_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, asset_id)
);

CREATE INDEX IF NOT EXISTS asset_profiles_updated_at_idx
    ON asset_profiles (tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS compensating_controls (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    name TEXT NOT NULL,
    control_type TEXT NOT NULL,
    scope_layer TEXT NOT NULL,
    effectiveness DOUBLE PRECISION NOT NULL,
    enabled BOOLEAN NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS compensating_controls_asset_idx
    ON compensating_controls (tenant_id, asset_id, enabled, updated_at DESC);
