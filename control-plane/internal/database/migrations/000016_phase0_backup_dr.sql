CREATE TABLE IF NOT EXISTS backup_snapshots (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'control_plane',
    storage_ref TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL DEFAULT '',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'completed',
    created_by TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS backup_snapshots_tenant_created_idx
    ON backup_snapshots (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS backup_snapshots_status_idx
    ON backup_snapshots (tenant_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS recovery_drills (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'completed',
    started_by TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    rto_seconds BIGINT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS recovery_drills_tenant_started_idx
    ON recovery_drills (tenant_id, started_at DESC);

CREATE INDEX IF NOT EXISTS recovery_drills_status_idx
    ON recovery_drills (tenant_id, status, started_at DESC);
