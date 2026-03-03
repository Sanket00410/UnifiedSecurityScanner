CREATE TABLE IF NOT EXISTS remediation_activities (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	remediation_id TEXT NOT NULL,
	event_type TEXT NOT NULL,
	actor TEXT NOT NULL DEFAULT '',
	comment TEXT NOT NULL DEFAULT '',
	metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remediation_activities_tenant_remediation
	ON remediation_activities (tenant_id, remediation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS remediation_verifications (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	remediation_id TEXT NOT NULL,
	finding_id TEXT NOT NULL,
	scan_job_id TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	outcome TEXT NOT NULL DEFAULT '',
	requested_by TEXT NOT NULL DEFAULT '',
	verified_by TEXT NOT NULL DEFAULT '',
	notes TEXT NOT NULL DEFAULT '',
	requested_at TIMESTAMPTZ NOT NULL,
	verified_at TIMESTAMPTZ NULL,
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remediation_verifications_tenant_remediation
	ON remediation_verifications (tenant_id, remediation_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS remediation_exceptions (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	remediation_id TEXT NOT NULL,
	finding_id TEXT NOT NULL,
	reason TEXT NOT NULL,
	reduction NUMERIC(6,2) NOT NULL,
	notes TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	requested_by TEXT NOT NULL DEFAULT '',
	decided_by TEXT NOT NULL DEFAULT '',
	expires_at TIMESTAMPTZ NULL,
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
	decided_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_remediation_exceptions_tenant_remediation
	ON remediation_exceptions (tenant_id, remediation_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS remediation_ticket_links (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	remediation_id TEXT NOT NULL,
	provider TEXT NOT NULL,
	external_id TEXT NOT NULL,
	title TEXT NOT NULL DEFAULT '',
	url TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remediation_ticket_links_tenant_remediation
	ON remediation_ticket_links (tenant_id, remediation_id, updated_at DESC);
