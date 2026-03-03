CREATE TABLE IF NOT EXISTS remediation_assignment_requests (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	remediation_id TEXT NOT NULL,
	finding_id TEXT NOT NULL,
	requested_by TEXT NOT NULL DEFAULT '',
	requested_owner TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	decided_by TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
	decided_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_remediation_assignment_requests_tenant_remediation
	ON remediation_assignment_requests (tenant_id, remediation_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS notification_events (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	remediation_id TEXT NOT NULL DEFAULT '',
	finding_id TEXT NOT NULL DEFAULT '',
	category TEXT NOT NULL,
	severity TEXT NOT NULL,
	channel TEXT NOT NULL,
	status TEXT NOT NULL,
	recipient TEXT NOT NULL DEFAULT '',
	subject TEXT NOT NULL,
	body TEXT NOT NULL DEFAULT '',
	dedup_key TEXT NOT NULL,
	acknowledged_by TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
	acknowledged_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_events_tenant_dedup
	ON notification_events (tenant_id, dedup_key);

CREATE INDEX IF NOT EXISTS idx_notification_events_tenant_updated
	ON notification_events (tenant_id, updated_at DESC);
