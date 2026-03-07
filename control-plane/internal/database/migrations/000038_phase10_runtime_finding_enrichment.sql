CREATE TABLE IF NOT EXISTS runtime_finding_enrichments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    telemetry_event_id TEXT NOT NULL,
    event_type TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    confidence_before TEXT NOT NULL DEFAULT '',
    confidence_after TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, finding_id, telemetry_event_id)
);

CREATE INDEX IF NOT EXISTS runtime_finding_enrichments_tenant_finding_idx
    ON runtime_finding_enrichments (tenant_id, finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS runtime_finding_enrichments_tenant_event_idx
    ON runtime_finding_enrichments (tenant_id, telemetry_event_id, created_at DESC);
