package jobs

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
)

var (
	backupSnapshotSequence uint64
	recoveryDrillSequence  uint64
)

func (s *Store) ListBackupSnapshotsForTenant(ctx context.Context, tenantID string, limit int) ([]models.BackupSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, scope, storage_ref, checksum_sha256, size_bytes, status, created_by, notes, created_at, completed_at
		FROM backup_snapshots
		WHERE tenant_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list backup snapshots: %w", err)
	}
	defer rows.Close()

	out := make([]models.BackupSnapshot, 0, limit)
	for rows.Next() {
		item, err := scanBackupSnapshot(rows)
		if err != nil {
			return nil, fmt.Errorf("scan backup snapshot: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate backup snapshots: %w", err)
	}

	return out, nil
}

func (s *Store) CreateBackupSnapshotForTenant(ctx context.Context, tenantID string, actor string, request models.CreateBackupSnapshotRequest) (models.BackupSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	now := time.Now().UTC()
	item := models.BackupSnapshot{
		ID:             nextBackupSnapshotID(),
		TenantID:       tenantID,
		Scope:          normalizeBackupScope(request.Scope),
		StorageRef:     strings.TrimSpace(request.StorageRef),
		ChecksumSHA256: strings.TrimSpace(strings.ToLower(request.ChecksumSHA256)),
		SizeBytes:      request.SizeBytes,
		Status:         normalizeBackupStatus(request.Status),
		CreatedBy:      actor,
		Notes:          strings.TrimSpace(request.Notes),
		CreatedAt:      now,
	}
	if request.CompletedAt != nil {
		completed := request.CompletedAt.UTC()
		item.CompletedAt = &completed
	} else if item.Status == "completed" {
		item.CompletedAt = &now
	}

	if item.StorageRef == "" {
		return models.BackupSnapshot{}, fmt.Errorf("storage_ref is required")
	}
	if item.SizeBytes < 0 {
		return models.BackupSnapshot{}, fmt.Errorf("size_bytes must be greater than or equal to zero")
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO backup_snapshots (
			id, tenant_id, scope, storage_ref, checksum_sha256, size_bytes, status, created_by, notes, created_at, completed_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)
	`, item.ID, item.TenantID, item.Scope, item.StorageRef, item.ChecksumSHA256, item.SizeBytes, item.Status, item.CreatedBy, item.Notes, item.CreatedAt, item.CompletedAt)
	if err != nil {
		return models.BackupSnapshot{}, fmt.Errorf("insert backup snapshot: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "backup_snapshot.created",
		SourceService: "control-plane",
		AggregateType: "backup_snapshot",
		AggregateID:   item.ID,
		Payload: map[string]any{
			"scope":       item.Scope,
			"storage_ref": item.StorageRef,
			"status":      item.Status,
			"created_by":  item.CreatedBy,
		},
		CreatedAt: now,
	})

	return item, nil
}

func (s *Store) ListRecoveryDrillsForTenant(ctx context.Context, tenantID string, limit int) ([]models.RecoveryDrill, error) {
	tenantID = strings.TrimSpace(tenantID)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, snapshot_id, status, started_by, notes, rto_seconds, started_at, completed_at
		FROM recovery_drills
		WHERE tenant_id = $1
		ORDER BY started_at DESC, id DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list recovery drills: %w", err)
	}
	defer rows.Close()

	out := make([]models.RecoveryDrill, 0, limit)
	for rows.Next() {
		item, err := scanRecoveryDrill(rows)
		if err != nil {
			return nil, fmt.Errorf("scan recovery drill: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recovery drills: %w", err)
	}

	return out, nil
}

func (s *Store) CreateRecoveryDrillForTenant(ctx context.Context, tenantID string, actor string, request models.CreateRecoveryDrillRequest) (models.RecoveryDrill, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	now := time.Now().UTC()
	item := models.RecoveryDrill{
		ID:         nextRecoveryDrillID(),
		TenantID:   tenantID,
		SnapshotID: strings.TrimSpace(request.SnapshotID),
		Status:     normalizeBackupStatus(request.Status),
		StartedBy:  actor,
		Notes:      strings.TrimSpace(request.Notes),
		RTOSeconds: request.RTOSeconds,
		StartedAt:  now,
	}
	if request.CompletedAt != nil {
		completed := request.CompletedAt.UTC()
		item.CompletedAt = &completed
	} else if item.Status == "completed" {
		item.CompletedAt = &now
	}
	if item.RTOSeconds < 0 {
		return models.RecoveryDrill{}, fmt.Errorf("rto_seconds must be greater than or equal to zero")
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO recovery_drills (
			id, tenant_id, snapshot_id, status, started_by, notes, rto_seconds, started_at, completed_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
	`, item.ID, item.TenantID, item.SnapshotID, item.Status, item.StartedBy, item.Notes, item.RTOSeconds, item.StartedAt, item.CompletedAt)
	if err != nil {
		return models.RecoveryDrill{}, fmt.Errorf("insert recovery drill: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "recovery_drill.created",
		SourceService: "control-plane",
		AggregateType: "recovery_drill",
		AggregateID:   item.ID,
		Payload: map[string]any{
			"snapshot_id": item.SnapshotID,
			"status":      item.Status,
			"started_by":  item.StartedBy,
		},
		CreatedAt: now,
	})

	return item, nil
}

func scanBackupSnapshot(row interface{ Scan(dest ...any) error }) (models.BackupSnapshot, error) {
	var item models.BackupSnapshot
	if err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.Scope,
		&item.StorageRef,
		&item.ChecksumSHA256,
		&item.SizeBytes,
		&item.Status,
		&item.CreatedBy,
		&item.Notes,
		&item.CreatedAt,
		&item.CompletedAt,
	); err != nil {
		return models.BackupSnapshot{}, err
	}

	return item, nil
}

func scanRecoveryDrill(row interface{ Scan(dest ...any) error }) (models.RecoveryDrill, error) {
	var item models.RecoveryDrill
	if err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.SnapshotID,
		&item.Status,
		&item.StartedBy,
		&item.Notes,
		&item.RTOSeconds,
		&item.StartedAt,
		&item.CompletedAt,
	); err != nil {
		return models.RecoveryDrill{}, err
	}

	return item, nil
}

func normalizeBackupScope(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "control_plane", "findings", "evidence", "full_platform":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "control_plane"
	}
}

func normalizeBackupStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "queued", "running", "completed", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "completed"
	}
}

func nextBackupSnapshotID() string {
	sequence := atomic.AddUint64(&backupSnapshotSequence, 1)
	return fmt.Sprintf("backup-snapshot-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextRecoveryDrillID() string {
	sequence := atomic.AddUint64(&recoveryDrillSequence, 1)
	return fmt.Sprintf("recovery-drill-%d-%06d", time.Now().UTC().Unix(), sequence)
}
