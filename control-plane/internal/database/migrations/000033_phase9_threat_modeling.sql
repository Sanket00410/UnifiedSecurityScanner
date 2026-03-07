CREATE TABLE IF NOT EXISTS design_reviews (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    title TEXT NOT NULL,
    service_name TEXT NOT NULL DEFAULT '',
    service_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft',
    threat_template TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    diagram_ref TEXT NOT NULL DEFAULT '',
    data_classification TEXT NOT NULL DEFAULT '',
    design_owner TEXT NOT NULL DEFAULT '',
    reviewer TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    submitted_at TIMESTAMPTZ NULL,
    approved_at TIMESTAMPTZ NULL,
    closed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS design_reviews_tenant_title_key
    ON design_reviews (tenant_id, title);

CREATE INDEX IF NOT EXISTS design_reviews_tenant_status_updated_idx
    ON design_reviews (tenant_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS design_review_threats (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    review_id TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    abuse_case TEXT NOT NULL DEFAULT '',
    impact TEXT NOT NULL DEFAULT '',
    likelihood TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    linked_asset_id TEXT NOT NULL DEFAULT '',
    linked_finding_id TEXT NOT NULL DEFAULT '',
    runtime_evidence_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    mitigation TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, review_id, title),
    CONSTRAINT design_review_threats_review_fk
        FOREIGN KEY (review_id)
        REFERENCES design_reviews (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS design_review_threats_tenant_review_status_idx
    ON design_review_threats (tenant_id, review_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS design_review_data_flows (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    review_id TEXT NOT NULL,
    entities_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    flows_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    trust_boundaries_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    notes TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, review_id),
    CONSTRAINT design_review_data_flows_review_fk
        FOREIGN KEY (review_id)
        REFERENCES design_reviews (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS design_review_data_flows_tenant_updated_idx
    ON design_review_data_flows (tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS design_control_mappings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    review_id TEXT NOT NULL,
    threat_id TEXT NOT NULL DEFAULT '',
    framework TEXT NOT NULL,
    control_id TEXT NOT NULL,
    control_title TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'planned',
    evidence_ref TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, review_id, threat_id, framework, control_id),
    CONSTRAINT design_control_mappings_review_fk
        FOREIGN KEY (review_id)
        REFERENCES design_reviews (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS design_control_mappings_tenant_review_framework_idx
    ON design_control_mappings (tenant_id, review_id, framework, updated_at DESC);
