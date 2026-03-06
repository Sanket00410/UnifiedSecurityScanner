CREATE TABLE IF NOT EXISTS kms_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT 'local',
    algorithm TEXT NOT NULL DEFAULT 'aes-256-gcm',
    purpose TEXT NOT NULL DEFAULT 'encrypt_decrypt',
    status TEXT NOT NULL DEFAULT 'active',
    key_salt TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, key_ref)
);

CREATE INDEX IF NOT EXISTS kms_keys_tenant_updated_idx
    ON kms_keys (tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS kms_operation_logs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    operation TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS kms_operation_logs_tenant_created_idx
    ON kms_operation_logs (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS secret_references (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    secret_path TEXT NOT NULL,
    secret_version TEXT NOT NULL DEFAULT '',
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS secret_references_tenant_updated_idx
    ON secret_references (tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS secret_leases (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    secret_reference_id TEXT NOT NULL REFERENCES secret_references (id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    lease_token_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    UNIQUE (tenant_id, lease_token_hash)
);

CREATE INDEX IF NOT EXISTS secret_leases_tenant_updated_idx
    ON secret_leases (tenant_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS secret_leases_reference_idx
    ON secret_leases (tenant_id, secret_reference_id, status, updated_at DESC);
