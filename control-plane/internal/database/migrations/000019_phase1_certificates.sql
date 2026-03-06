CREATE TABLE IF NOT EXISTS workload_certificates (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    issued_by TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    revoked_reason TEXT NOT NULL DEFAULT '',
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, serial_number)
);

CREATE INDEX IF NOT EXISTS workload_certificates_tenant_subject_idx
    ON workload_certificates (tenant_id, subject_type, subject_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS workload_certificates_tenant_status_idx
    ON workload_certificates (tenant_id, status, expires_at, issued_at DESC);
