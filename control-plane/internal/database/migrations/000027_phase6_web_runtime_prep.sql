CREATE TABLE IF NOT EXISTS web_targets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'webapp',
    base_url TEXT NOT NULL,
    api_schema_url TEXT NOT NULL DEFAULT '',
    in_scope_patterns TEXT[] NOT NULL DEFAULT '{}'::text[],
    out_of_scope_patterns TEXT[] NOT NULL DEFAULT '{}'::text[],
    labels_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS web_targets_tenant_updated_idx
    ON web_targets (tenant_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS web_targets_tenant_type_idx
    ON web_targets (tenant_id, target_type);

CREATE TABLE IF NOT EXISTS web_auth_profiles (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    auth_type TEXT NOT NULL DEFAULT 'form',
    login_url TEXT NOT NULL DEFAULT '',
    username_secret_ref TEXT NOT NULL DEFAULT '',
    password_secret_ref TEXT NOT NULL DEFAULT '',
    bearer_token_secret_ref TEXT NOT NULL DEFAULT '',
    csrf_mode TEXT NOT NULL DEFAULT 'auto',
    session_bootstrap_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    test_personas_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    token_refresh_strategy TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS web_auth_profiles_tenant_updated_idx
    ON web_auth_profiles (tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS web_crawl_policies (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    web_target_id TEXT NOT NULL REFERENCES web_targets(id) ON DELETE CASCADE,
    auth_profile_id TEXT NULL REFERENCES web_auth_profiles(id) ON DELETE SET NULL,
    safe_mode BOOLEAN NOT NULL DEFAULT TRUE,
    max_depth BIGINT NOT NULL DEFAULT 3,
    max_requests BIGINT NOT NULL DEFAULT 500,
    request_budget_per_minute BIGINT NOT NULL DEFAULT 120,
    allow_paths TEXT[] NOT NULL DEFAULT '{}'::text[],
    deny_paths TEXT[] NOT NULL DEFAULT '{}'::text[],
    seed_urls TEXT[] NOT NULL DEFAULT '{}'::text[],
    headers_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, web_target_id)
);

CREATE INDEX IF NOT EXISTS web_crawl_policies_tenant_updated_idx
    ON web_crawl_policies (tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS web_coverage_baselines (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    web_target_id TEXT NOT NULL REFERENCES web_targets(id) ON DELETE CASCADE,
    expected_route_count BIGINT NOT NULL DEFAULT 0,
    expected_api_operation_count BIGINT NOT NULL DEFAULT 0,
    expected_auth_state_count BIGINT NOT NULL DEFAULT 0,
    minimum_route_coverage DOUBLE PRECISION NOT NULL DEFAULT 0,
    minimum_api_coverage DOUBLE PRECISION NOT NULL DEFAULT 0,
    minimum_auth_coverage DOUBLE PRECISION NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, web_target_id)
);

CREATE INDEX IF NOT EXISTS web_coverage_baselines_tenant_updated_idx
    ON web_coverage_baselines (tenant_id, updated_at DESC);
