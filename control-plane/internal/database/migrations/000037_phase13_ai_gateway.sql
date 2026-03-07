CREATE TABLE IF NOT EXISTS ai_gateway_policies (
    tenant_id TEXT PRIMARY KEY,
    default_model TEXT NOT NULL DEFAULT 'gpt-4o-mini',
    allowed_models TEXT[] NOT NULL DEFAULT ARRAY['gpt-4o-mini']::text[],
    max_input_chars BIGINT NOT NULL DEFAULT 12000,
    max_output_chars BIGINT NOT NULL DEFAULT 3000,
    require_grounding BOOLEAN NOT NULL DEFAULT TRUE,
    require_evidence_refs BOOLEAN NOT NULL DEFAULT TRUE,
    redact_secrets BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_triage_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    request_kind TEXT NOT NULL,
    model TEXT NOT NULL,
    input_text TEXT NOT NULL,
    evidence_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    finding_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    response_text TEXT NOT NULL,
    safety_state TEXT NOT NULL DEFAULT 'grounded',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ai_triage_requests_tenant_created_idx
    ON ai_triage_requests (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ai_triage_requests_tenant_kind_created_idx
    ON ai_triage_requests (tenant_id, request_kind, created_at DESC);
