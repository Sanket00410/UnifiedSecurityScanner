CREATE TABLE IF NOT EXISTS validation_execution_envelopes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL REFERENCES validation_engagements(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'draft',
    policy_pack_ref TEXT NOT NULL DEFAULT '',
    allowed_tools TEXT[] NOT NULL DEFAULT '{}'::text[],
    requires_step_approval BOOLEAN NOT NULL DEFAULT FALSE,
    max_runtime_seconds BIGINT NOT NULL DEFAULT 0,
    network_scope TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    approved_by TEXT NOT NULL DEFAULT '',
    approved_at TIMESTAMPTZ NULL,
    activated_by TEXT NOT NULL DEFAULT '',
    activated_at TIMESTAMPTZ NULL,
    closed_by TEXT NOT NULL DEFAULT '',
    closed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, engagement_id)
);

CREATE INDEX IF NOT EXISTS validation_execution_envelopes_tenant_status_updated_idx
    ON validation_execution_envelopes (tenant_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS validation_plan_steps (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL REFERENCES validation_engagements(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    adapter_id TEXT NOT NULL DEFAULT '',
    target_kind TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    depends_on TEXT[] NOT NULL DEFAULT '{}'::text[],
    status TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT NOT NULL DEFAULT '',
    decided_by TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS validation_plan_steps_tenant_engagement_status_idx
    ON validation_plan_steps (tenant_id, engagement_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS validation_plan_steps_tenant_adapter_idx
    ON validation_plan_steps (tenant_id, adapter_id, updated_at DESC);
