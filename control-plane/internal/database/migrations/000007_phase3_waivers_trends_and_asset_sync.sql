ALTER TABLE asset_profiles
	ADD COLUMN IF NOT EXISTS owner_hierarchy_json JSONB NOT NULL DEFAULT '[]'::jsonb,
	ADD COLUMN IF NOT EXISTS service_name TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS service_tier TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS service_criticality_class TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS external_source TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS external_reference TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ NULL;

CREATE TABLE IF NOT EXISTS finding_waivers (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	finding_id TEXT NOT NULL,
	remediation_id TEXT NOT NULL DEFAULT '',
	policy_approval_id TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL,
	reduction NUMERIC(6,2) NOT NULL,
	status TEXT NOT NULL,
	expires_at TIMESTAMPTZ NULL,
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_waivers_tenant_finding
	ON finding_waivers (tenant_id, finding_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS finding_occurrences (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	finding_id TEXT NOT NULL,
	finding_key TEXT NOT NULL,
	scan_job_id TEXT NOT NULL,
	task_id TEXT NOT NULL,
	observed_status TEXT NOT NULL,
	observed_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_occurrences_tenant_observed
	ON finding_occurrences (tenant_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_finding_occurrences_tenant_finding
	ON finding_occurrences (tenant_id, finding_id, observed_at DESC);
