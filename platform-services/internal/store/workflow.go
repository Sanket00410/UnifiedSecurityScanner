package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/platform-services/internal/models"
)

func (s *Store) CreateNotification(ctx context.Context, tenantID string, actor string, request models.CreateNotificationRequest) (models.Notification, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	title := strings.TrimSpace(request.Title)
	if title == "" {
		return models.Notification{}, errors.New("notification title is required")
	}

	now := time.Now().UTC()
	notification := models.Notification{
		ID:        nextID("notification"),
		TenantID:  normalizedTenantID,
		Severity:  normalizeSeverity(request.Severity),
		Title:     title,
		Body:      strings.TrimSpace(request.Body),
		Status:    models.NotificationStatusQueued,
		OwnerTeam: strings.TrimSpace(request.OwnerTeam),
		Metadata:  cloneAnyMap(request.Metadata),
		CreatedBy: normalizeActor(actor),
		CreatedAt: now,
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.Notification{}, fmt.Errorf("begin create notification tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO ps_notifications (
			id, tenant_id, severity, title, body,
			status, owner_team, metadata_json,
			created_by, created_at, acknowledged_at, acknowledged_by
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8::jsonb,
			$9, $10, NULL, ''
		)
	`,
		notification.ID,
		notification.TenantID,
		notification.Severity,
		notification.Title,
		notification.Body,
		notification.Status,
		notification.OwnerTeam,
		marshalAnyMap(notification.Metadata),
		notification.CreatedBy,
		notification.CreatedAt,
	)
	if err != nil {
		return models.Notification{}, fmt.Errorf("insert notification: %w", err)
	}

	payload := map[string]any{
		"notification_id": notification.ID,
		"title":           notification.Title,
		"body":            notification.Body,
		"severity":        notification.Severity,
		"owner_team":      notification.OwnerTeam,
		"channel":         normalizeChannel(request.Channel),
		"metadata":        cloneAnyMap(notification.Metadata),
	}
	_, err = s.createJobTx(ctx, tx, notification.TenantID, actor, models.EnqueuePlatformJobRequest{
		JobKind:     models.JobKindNotificationDispatch,
		ConnectorID: strings.TrimSpace(request.ConnectorID),
		Payload:     payload,
	})
	if err != nil {
		return models.Notification{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.Notification{}, fmt.Errorf("commit create notification tx: %w", err)
	}

	return notification, nil
}

func (s *Store) ListNotifications(ctx context.Context, tenantID string, status string, limit int) ([]models.Notification, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	normalizedLimit := normalizeLimit(limit, defaultListLimit)
	normalizedStatus := normalizeStatus(status)

	query := `
		SELECT
			id, tenant_id, severity, title, body, status, owner_team,
			metadata_json, created_by, created_at, acknowledged_at, acknowledged_by
		FROM ps_notifications
		WHERE tenant_id = $1
	`
	args := []any{normalizedTenantID}
	if normalizedStatus != "" {
		query += " AND status = $2 ORDER BY created_at DESC LIMIT $3"
		args = append(args, normalizedStatus, normalizedLimit)
	} else {
		query += " ORDER BY created_at DESC LIMIT $2"
		args = append(args, normalizedLimit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list notifications: %w", err)
	}
	defer rows.Close()

	results := make([]models.Notification, 0, normalizedLimit)
	for rows.Next() {
		item, scanErr := scanNotification(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notifications: %w", err)
	}
	return results, nil
}

func (s *Store) AcknowledgeNotification(ctx context.Context, tenantID string, notificationID string, actor string) (models.Notification, bool, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE ps_notifications
		SET
			status = $3,
			acknowledged_at = $4,
			acknowledged_by = $5
		WHERE tenant_id = $1 AND id = $2
		RETURNING
			id, tenant_id, severity, title, body, status, owner_team,
			metadata_json, created_by, created_at, acknowledged_at, acknowledged_by
	`,
		s.ResolveTenantID(tenantID),
		strings.TrimSpace(notificationID),
		models.NotificationStatusAcknowledged,
		time.Now().UTC(),
		normalizeActor(actor),
	)
	notification, err := scanNotification(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Notification{}, false, nil
		}
		return models.Notification{}, false, err
	}
	return notification, true, nil
}

func (s *Store) CreateAuditExport(ctx context.Context, tenantID string, actor string, request models.CreateAuditExportRequest) (models.AuditExport, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	format := normalizeExportFormat(request.Format)
	now := time.Now().UTC()

	record := models.AuditExport{
		ID:             nextID("audit-export"),
		TenantID:       normalizedTenantID,
		Format:         format,
		DestinationRef: strings.TrimSpace(request.DestinationRef),
		Filters:        cloneAnyMap(request.Filters),
		Status:         models.AuditExportStatusQueued,
		RequestedBy:    normalizeActor(actor),
		RequestedAt:    now,
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.AuditExport{}, fmt.Errorf("begin create audit export tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO ps_audit_exports (
			id, tenant_id, format, destination_ref, filters_json,
			status, requested_by, requested_at, completed_at, file_ref, error_message
		) VALUES (
			$1, $2, $3, $4, $5::jsonb,
			$6, $7, $8, NULL, '', ''
		)
	`,
		record.ID,
		record.TenantID,
		record.Format,
		record.DestinationRef,
		marshalAnyMap(record.Filters),
		record.Status,
		record.RequestedBy,
		record.RequestedAt,
	)
	if err != nil {
		return models.AuditExport{}, fmt.Errorf("insert audit export: %w", err)
	}

	payload := map[string]any{
		"audit_export_id": record.ID,
		"format":          record.Format,
		"destination_ref": record.DestinationRef,
		"filters":         cloneAnyMap(record.Filters),
	}
	_, err = s.createJobTx(ctx, tx, record.TenantID, actor, models.EnqueuePlatformJobRequest{
		JobKind:     models.JobKindAuditExportExecute,
		ConnectorID: strings.TrimSpace(request.ConnectorID),
		Payload:     payload,
	})
	if err != nil {
		return models.AuditExport{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.AuditExport{}, fmt.Errorf("commit create audit export tx: %w", err)
	}
	return record, nil
}

func (s *Store) ListAuditExports(ctx context.Context, tenantID string, status string, limit int) ([]models.AuditExport, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	normalizedStatus := normalizeStatus(status)
	normalizedLimit := normalizeLimit(limit, defaultListLimit)

	query := `
		SELECT
			id, tenant_id, format, destination_ref, filters_json, status,
			requested_by, requested_at, completed_at, file_ref, error_message
		FROM ps_audit_exports
		WHERE tenant_id = $1
	`
	args := []any{normalizedTenantID}
	if normalizedStatus != "" {
		query += " AND status = $2 ORDER BY requested_at DESC LIMIT $3"
		args = append(args, normalizedStatus, normalizedLimit)
	} else {
		query += " ORDER BY requested_at DESC LIMIT $2"
		args = append(args, normalizedLimit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit exports: %w", err)
	}
	defer rows.Close()

	results := make([]models.AuditExport, 0, normalizedLimit)
	for rows.Next() {
		item, scanErr := scanAuditExport(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit exports: %w", err)
	}
	return results, nil
}

func (s *Store) GetAuditExport(ctx context.Context, tenantID string, exportID string) (models.AuditExport, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT
			id, tenant_id, format, destination_ref, filters_json, status,
			requested_by, requested_at, completed_at, file_ref, error_message
		FROM ps_audit_exports
		WHERE tenant_id = $1 AND id = $2
	`,
		s.ResolveTenantID(tenantID),
		strings.TrimSpace(exportID),
	)
	record, err := scanAuditExport(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.AuditExport{}, false, nil
		}
		return models.AuditExport{}, false, err
	}
	return record, true, nil
}

func (s *Store) ListAuditExportEvents(ctx context.Context, tenantID string, filters map[string]any, limit int) ([]map[string]any, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	normalizedLimit := normalizeLimit(limit, defaultExportEventRows)
	parsedFilters := cloneAnyMap(filters)
	jobKindFilter := strings.TrimSpace(extractString(parsedFilters, "job_kind"))
	statusFilter := normalizeStatus(extractString(parsedFilters, "job_status"))

	query := `
		SELECT
			a.id,
			a.job_id,
			j.job_kind,
			j.status,
			a.worker_id,
			a.success,
			a.response_status,
			a.error_message,
			a.duration_ms,
			a.attempted_at
		FROM ps_platform_job_attempts a
		JOIN ps_platform_jobs j ON j.id = a.job_id
		WHERE a.tenant_id = $1
	`
	args := []any{normalizedTenantID}
	argPos := 2
	if jobKindFilter != "" {
		query += fmt.Sprintf(" AND j.job_kind = $%d", argPos)
		args = append(args, normalizeJobKind(jobKindFilter))
		argPos++
	}
	if statusFilter != "" {
		query += fmt.Sprintf(" AND j.status = $%d", argPos)
		args = append(args, statusFilter)
		argPos++
	}
	query += fmt.Sprintf(" ORDER BY a.attempted_at DESC LIMIT $%d", argPos)
	args = append(args, normalizedLimit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit export events: %w", err)
	}
	defer rows.Close()

	results := make([]map[string]any, 0, normalizedLimit)
	for rows.Next() {
		var (
			id             string
			jobID          string
			jobKind        string
			jobStatus      string
			workerID       string
			success        bool
			responseStatus int
			errorMessage   string
			durationMS     int64
			attemptedAt    time.Time
		)
		if err := rows.Scan(
			&id,
			&jobID,
			&jobKind,
			&jobStatus,
			&workerID,
			&success,
			&responseStatus,
			&errorMessage,
			&durationMS,
			&attemptedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit export event: %w", err)
		}
		results = append(results, map[string]any{
			"attempt_id":      id,
			"job_id":          jobID,
			"job_kind":        jobKind,
			"job_status":      jobStatus,
			"worker_id":       workerID,
			"success":         success,
			"response_status": responseStatus,
			"error_message":   errorMessage,
			"duration_ms":     durationMS,
			"attempted_at":    attemptedAt.Format(time.RFC3339Nano),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit export events: %w", err)
	}
	return results, nil
}

func (s *Store) CreateSyncRun(ctx context.Context, tenantID string, actor string, request models.CreateSyncRunRequest) (models.SyncRun, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	syncKind := normalizeSyncKind(request.SyncKind)
	if syncKind == "" {
		return models.SyncRun{}, errors.New("sync kind is required")
	}
	now := time.Now().UTC()

	run := models.SyncRun{
		ID:         nextID("sync-run"),
		TenantID:   normalizedTenantID,
		SyncKind:   syncKind,
		SourceRef:  strings.TrimSpace(request.SourceRef),
		VersionTag: strings.TrimSpace(request.VersionTag),
		Metadata:   cloneAnyMap(request.Metadata),
		Status:     models.SyncStatusQueued,
		StartedBy:  normalizeActor(actor),
		StartedAt:  now,
		Summary:    map[string]any{},
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.SyncRun{}, fmt.Errorf("begin create sync run tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO ps_sync_runs (
			id, tenant_id, sync_kind, source_ref, version_tag,
			metadata_json, status, started_by, started_at, completed_at, summary_json, error_message
		) VALUES (
			$1, $2, $3, $4, $5,
			$6::jsonb, $7, $8, $9, NULL, '{}'::jsonb, ''
		)
	`,
		run.ID,
		run.TenantID,
		run.SyncKind,
		run.SourceRef,
		run.VersionTag,
		marshalAnyMap(run.Metadata),
		run.Status,
		run.StartedBy,
		run.StartedAt,
	)
	if err != nil {
		return models.SyncRun{}, fmt.Errorf("insert sync run: %w", err)
	}

	payload := map[string]any{
		"sync_run_id": run.ID,
		"sync_kind":   run.SyncKind,
		"source_ref":  run.SourceRef,
		"version_tag": run.VersionTag,
		"metadata":    cloneAnyMap(run.Metadata),
	}
	_, err = s.createJobTx(ctx, tx, run.TenantID, actor, models.EnqueuePlatformJobRequest{
		JobKind:     models.JobKindFeedSync,
		ConnectorID: strings.TrimSpace(request.ConnectorID),
		Payload:     payload,
	})
	if err != nil {
		return models.SyncRun{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.SyncRun{}, fmt.Errorf("commit create sync run tx: %w", err)
	}
	return run, nil
}

func (s *Store) ListSyncRuns(ctx context.Context, tenantID string, syncKind string, status string, limit int) ([]models.SyncRun, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	normalizedSyncKind := normalizeSyncKind(syncKind)
	normalizedStatus := normalizeStatus(status)
	normalizedLimit := normalizeLimit(limit, defaultListLimit)

	query := `
		SELECT
			id, tenant_id, sync_kind, source_ref, version_tag,
			metadata_json, status, started_by, started_at, completed_at, summary_json, error_message
		FROM ps_sync_runs
		WHERE tenant_id = $1
	`
	args := []any{normalizedTenantID}
	nextIndex := 2
	if normalizedSyncKind != "" {
		query += fmt.Sprintf(" AND sync_kind = $%d", nextIndex)
		args = append(args, normalizedSyncKind)
		nextIndex++
	}
	if normalizedStatus != "" {
		query += fmt.Sprintf(" AND status = $%d", nextIndex)
		args = append(args, normalizedStatus)
		nextIndex++
	}
	query += fmt.Sprintf(" ORDER BY started_at DESC LIMIT $%d", nextIndex)
	args = append(args, normalizedLimit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list sync runs: %w", err)
	}
	defer rows.Close()

	results := make([]models.SyncRun, 0, normalizedLimit)
	for rows.Next() {
		item, scanErr := scanSyncRun(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sync runs: %w", err)
	}
	return results, nil
}

func (s *Store) MetricsSnapshot(ctx context.Context) (models.PlatformMetrics, error) {
	metrics := models.PlatformMetrics{
		QueueStats:           []models.QueueStat{},
		TimestampUnixSeconds: time.Now().UTC().Unix(),
	}

	rows, err := s.pool.Query(ctx, `
		SELECT status, COUNT(*)
		FROM ps_platform_jobs
		GROUP BY status
	`)
	if err != nil {
		return metrics, fmt.Errorf("metrics queue stats: %w", err)
	}
	for rows.Next() {
		var stat models.QueueStat
		if err := rows.Scan(&stat.Status, &stat.Count); err != nil {
			rows.Close()
			return metrics, fmt.Errorf("scan queue stat: %w", err)
		}
		metrics.QueueStats = append(metrics.QueueStats, stat)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return metrics, fmt.Errorf("iterate queue stats: %w", err)
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM ps_notifications WHERE status = $1
	`, models.NotificationStatusQueued).Scan(&metrics.NotificationsOpen); err != nil {
		return metrics, fmt.Errorf("metrics notifications: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM ps_audit_exports WHERE status = $1
	`, models.AuditExportStatusQueued).Scan(&metrics.AuditExportsPending); err != nil {
		return metrics, fmt.Errorf("metrics audit exports: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM ps_sync_runs WHERE status = $1
	`, models.SyncStatusQueued).Scan(&metrics.SyncRunsPending); err != nil {
		return metrics, fmt.Errorf("metrics sync runs: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM ps_connectors WHERE enabled = TRUE
	`).Scan(&metrics.ConnectorCount); err != nil {
		return metrics, fmt.Errorf("metrics connectors: %w", err)
	}

	return metrics, nil
}
