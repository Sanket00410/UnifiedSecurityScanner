CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scope TEXT NOT NULL,
    mode TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    rules_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS policies_updated_at_idx
    ON policies (updated_at DESC);

CREATE TABLE IF NOT EXISTS remediation_actions (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL,
    due_at TIMESTAMPTZ NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS remediation_actions_updated_at_idx
    ON remediation_actions (updated_at DESC);

CREATE INDEX IF NOT EXISTS remediation_actions_finding_id_idx
    ON remediation_actions (finding_id);
