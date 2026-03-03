CREATE TABLE IF NOT EXISTS remediation_evidence (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	remediation_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	ref TEXT NOT NULL,
	summary TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remediation_evidence_tenant_remediation
	ON remediation_evidence (tenant_id, remediation_id, updated_at DESC);
