CREATE TABLE IF NOT EXISTS validation_engagements (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    target_kind TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    policy_pack_ref TEXT NOT NULL DEFAULT '',
    allowed_tools TEXT[] NOT NULL DEFAULT '{}'::text[],
    requires_manual_approval BOOLEAN NOT NULL DEFAULT TRUE,
    notes TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL DEFAULT '',
    approved_by TEXT NOT NULL DEFAULT '',
    approved_at TIMESTAMPTZ NULL,
    activated_by TEXT NOT NULL DEFAULT '',
    activated_at TIMESTAMPTZ NULL,
    closed_by TEXT NOT NULL DEFAULT '',
    closed_at TIMESTAMPTZ NULL,
    start_at TIMESTAMPTZ NULL,
    end_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS validation_engagements_tenant_status_updated_idx
    ON validation_engagements (tenant_id, status, updated_at DESC);
