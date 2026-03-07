CREATE TABLE IF NOT EXISTS compliance_control_mappings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    source_id TEXT NOT NULL,
    finding_id TEXT NOT NULL DEFAULT '',
    framework TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    control_id TEXT NOT NULL,
    control_title TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'identified',
    evidence_ref TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, source_kind, source_id, framework, control_id)
);

CREATE INDEX IF NOT EXISTS compliance_control_mappings_tenant_framework_idx
    ON compliance_control_mappings (tenant_id, framework, updated_at DESC);

CREATE INDEX IF NOT EXISTS compliance_control_mappings_tenant_status_idx
    ON compliance_control_mappings (tenant_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS compliance_control_mappings_tenant_finding_idx
    ON compliance_control_mappings (tenant_id, finding_id, updated_at DESC);
