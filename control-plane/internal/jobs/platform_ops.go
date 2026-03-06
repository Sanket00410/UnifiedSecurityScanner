package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListPlatformEventsForTenant(ctx context.Context, tenantID string, eventType string, limit int) ([]models.PlatformEvent, error) {
	tenantID = strings.TrimSpace(tenantID)
	eventType = strings.TrimSpace(eventType)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, event_type, source_service, aggregate_type, aggregate_id, payload_json, created_at
		FROM platform_events
		WHERE (tenant_id = $1 OR tenant_id = '')
		  AND ($2 = '' OR event_type = $2)
		ORDER BY created_at DESC, id DESC
		LIMIT $3
	`, tenantID, eventType, limit)
	if err != nil {
		return nil, fmt.Errorf("list platform events: %w", err)
	}
	defer rows.Close()

	out := make([]models.PlatformEvent, 0, limit)
	for rows.Next() {
		event, err := scanPlatformEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan platform event row: %w", err)
		}
		out = append(out, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate platform events: %w", err)
	}

	return out, nil
}

func (s *Store) GetTenantOperationsSnapshot(ctx context.Context, tenantID string) (models.TenantOperationsSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	limits, err := s.loadTenantLimits(ctx, tenantID)
	if err != nil {
		return models.TenantOperationsSnapshot{}, err
	}

	var usage models.TenantUsage
	err = s.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM scan_jobs WHERE tenant_id = $1) AS total_scan_jobs,
			(SELECT COUNT(*) FROM scan_jobs WHERE tenant_id = $1 AND status IN ('queued','running')) AS active_scan_jobs,
			(SELECT COUNT(*) FROM scan_targets WHERE tenant_id = $1) AS scan_targets,
			(SELECT COUNT(*) FROM ingestion_sources WHERE tenant_id = $1) AS ingestion_sources
	`, tenantID).Scan(
		&usage.TotalScanJobs,
		&usage.ActiveScanJobs,
		&usage.ScanTargets,
		&usage.IngestionSources,
	)
	if err != nil {
		return models.TenantOperationsSnapshot{}, fmt.Errorf("load tenant usage snapshot: %w", err)
	}

	return models.TenantOperationsSnapshot{
		TenantID: tenantID,
		Limits:   limits,
		Usage:    usage,
	}, nil
}

func (s *Store) UpdateTenantLimitsForTenant(ctx context.Context, tenantID string, actor string, request models.UpdateTenantLimitsRequest) (models.TenantOperationsSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	now := time.Now().UTC()

	current, err := s.loadTenantLimits(ctx, tenantID)
	if err != nil {
		return models.TenantOperationsSnapshot{}, err
	}

	next := current
	next.TenantID = tenantID
	next.UpdatedAt = now
	if actor != "" {
		next.UpdatedBy = actor
	}

	if request.MaxTotalScanJobs != nil {
		if *request.MaxTotalScanJobs < 0 {
			return models.TenantOperationsSnapshot{}, fmt.Errorf("max_total_scan_jobs must be greater than or equal to zero")
		}
		next.MaxTotalScanJobs = *request.MaxTotalScanJobs
	}
	if request.MaxActiveScanJobs != nil {
		if *request.MaxActiveScanJobs < 0 {
			return models.TenantOperationsSnapshot{}, fmt.Errorf("max_active_scan_jobs must be greater than or equal to zero")
		}
		next.MaxActiveScanJobs = *request.MaxActiveScanJobs
	}
	if request.MaxScanJobsPerMinute != nil {
		if *request.MaxScanJobsPerMinute < 0 {
			return models.TenantOperationsSnapshot{}, fmt.Errorf("max_scan_jobs_per_minute must be greater than or equal to zero")
		}
		next.MaxScanJobsPerMinute = *request.MaxScanJobsPerMinute
	}
	if request.MaxScanTargets != nil {
		if *request.MaxScanTargets < 0 {
			return models.TenantOperationsSnapshot{}, fmt.Errorf("max_scan_targets must be greater than or equal to zero")
		}
		next.MaxScanTargets = *request.MaxScanTargets
	}
	if request.MaxIngestionSources != nil {
		if *request.MaxIngestionSources < 0 {
			return models.TenantOperationsSnapshot{}, fmt.Errorf("max_ingestion_sources must be greater than or equal to zero")
		}
		next.MaxIngestionSources = *request.MaxIngestionSources
	}

	if next.UpdatedBy == "" {
		next.UpdatedBy = current.UpdatedBy
	}
	if next.UpdatedBy == "" {
		next.UpdatedBy = "system"
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO tenant_limits (
			tenant_id, max_total_scan_jobs, max_active_scan_jobs, max_scan_jobs_per_minute,
			max_scan_targets, max_ingestion_sources, updated_by, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
		ON CONFLICT (tenant_id) DO UPDATE SET
			max_total_scan_jobs = EXCLUDED.max_total_scan_jobs,
			max_active_scan_jobs = EXCLUDED.max_active_scan_jobs,
			max_scan_jobs_per_minute = EXCLUDED.max_scan_jobs_per_minute,
			max_scan_targets = EXCLUDED.max_scan_targets,
			max_ingestion_sources = EXCLUDED.max_ingestion_sources,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
	`, next.TenantID, next.MaxTotalScanJobs, next.MaxActiveScanJobs, next.MaxScanJobsPerMinute, next.MaxScanTargets, next.MaxIngestionSources, next.UpdatedBy, next.UpdatedAt)
	if err != nil {
		return models.TenantOperationsSnapshot{}, fmt.Errorf("upsert tenant limits: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "tenant_limits.updated",
		SourceService: "control-plane",
		AggregateType: "tenant",
		AggregateID:   tenantID,
		Payload: map[string]any{
			"max_total_scan_jobs":      next.MaxTotalScanJobs,
			"max_active_scan_jobs":     next.MaxActiveScanJobs,
			"max_scan_jobs_per_minute": next.MaxScanJobsPerMinute,
			"max_scan_targets":         next.MaxScanTargets,
			"max_ingestion_sources":    next.MaxIngestionSources,
			"updated_by":               next.UpdatedBy,
		},
		CreatedAt: now,
	})

	return s.GetTenantOperationsSnapshot(ctx, tenantID)
}

func (s *Store) GetOperationalMetrics(ctx context.Context) (models.OperationalMetrics, error) {
	healthyCutoff := time.Now().UTC().Add(-s.workerHeartbeatTTL)

	var metrics models.OperationalMetrics
	err := s.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM workers) AS workers_total,
			(SELECT COUNT(*) FROM workers WHERE last_heartbeat_at >= $1) AS workers_healthy,
			(SELECT COUNT(*) FROM scan_jobs) AS scan_jobs_total,
			(SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued') AS scan_jobs_queued,
			(SELECT COUNT(*) FROM scan_jobs WHERE status = 'running') AS scan_jobs_running,
			(SELECT COUNT(*) FROM scan_jobs WHERE status = 'completed') AS scan_jobs_completed,
			(SELECT COUNT(*) FROM scan_jobs WHERE status = 'failed') AS scan_jobs_failed,
			(SELECT COUNT(*) FROM scan_targets) AS scan_targets_total,
			(SELECT COUNT(*) FROM ingestion_sources) AS ingestion_sources_total,
			(SELECT COUNT(*) FROM ingestion_events) AS ingestion_events_total,
			(SELECT COUNT(*) FROM platform_events) AS platform_events_total
	`, healthyCutoff).Scan(
		&metrics.WorkersTotal,
		&metrics.WorkersHealthy,
		&metrics.ScanJobsTotal,
		&metrics.ScanJobsQueued,
		&metrics.ScanJobsRunning,
		&metrics.ScanJobsCompleted,
		&metrics.ScanJobsFailed,
		&metrics.ScanTargetsTotal,
		&metrics.IngestionSources,
		&metrics.IngestionEvents,
		&metrics.PlatformEventsTotal,
	)
	if err != nil {
		return models.OperationalMetrics{}, fmt.Errorf("load operational metrics: %w", err)
	}

	return metrics, nil
}

func (s *Store) enforceScanJobTenantLimitsTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil
	}

	limits, err := loadTenantLimitsTx(ctx, tx, tenantID)
	if err != nil {
		return err
	}

	var total, active int64
	err = tx.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM scan_jobs WHERE tenant_id = $1) AS total_scan_jobs,
			(SELECT COUNT(*) FROM scan_jobs WHERE tenant_id = $1 AND status IN ('queued','running')) AS active_scan_jobs
	`, tenantID).Scan(&total, &active)
	if err != nil {
		return fmt.Errorf("load tenant scan job usage: %w", err)
	}

	if limits.MaxTotalScanJobs > 0 && total >= limits.MaxTotalScanJobs {
		return &TenantLimitExceededError{
			TenantID: tenantID,
			Metric:   "max_total_scan_jobs",
			Limit:    limits.MaxTotalScanJobs,
			Current:  total,
		}
	}
	if limits.MaxActiveScanJobs > 0 && active >= limits.MaxActiveScanJobs {
		return &TenantLimitExceededError{
			TenantID: tenantID,
			Metric:   "max_active_scan_jobs",
			Limit:    limits.MaxActiveScanJobs,
			Current:  active,
		}
	}
	if limits.MaxScanJobsPerMinute > 0 {
		cutoff := time.Now().UTC().Add(-1 * time.Minute)
		var recent int64
		err := tx.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM scan_jobs
			WHERE tenant_id = $1
			  AND requested_at >= $2
		`, tenantID, cutoff).Scan(&recent)
		if err != nil {
			return fmt.Errorf("load tenant scan job rate usage: %w", err)
		}
		if recent >= limits.MaxScanJobsPerMinute {
			return &TenantLimitExceededError{
				TenantID: tenantID,
				Metric:   "max_scan_jobs_per_minute",
				Limit:    limits.MaxScanJobsPerMinute,
				Current:  recent,
			}
		}
	}

	return nil
}

func (s *Store) enforceScanTargetLimit(ctx context.Context, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil
	}

	limits, err := s.loadTenantLimits(ctx, tenantID)
	if err != nil {
		return err
	}
	if limits.MaxScanTargets <= 0 {
		return nil
	}

	var current int64
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM scan_targets
		WHERE tenant_id = $1
	`, tenantID).Scan(&current); err != nil {
		return fmt.Errorf("load tenant scan target usage: %w", err)
	}

	if current >= limits.MaxScanTargets {
		return &TenantLimitExceededError{
			TenantID: tenantID,
			Metric:   "max_scan_targets",
			Limit:    limits.MaxScanTargets,
			Current:  current,
		}
	}

	return nil
}

func (s *Store) enforceIngestionSourceLimit(ctx context.Context, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil
	}

	limits, err := s.loadTenantLimits(ctx, tenantID)
	if err != nil {
		return err
	}
	if limits.MaxIngestionSources <= 0 {
		return nil
	}

	var current int64
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM ingestion_sources
		WHERE tenant_id = $1
	`, tenantID).Scan(&current); err != nil {
		return fmt.Errorf("load tenant ingestion source usage: %w", err)
	}

	if current >= limits.MaxIngestionSources {
		return &TenantLimitExceededError{
			TenantID: tenantID,
			Metric:   "max_ingestion_sources",
			Limit:    limits.MaxIngestionSources,
			Current:  current,
		}
	}

	return nil
}

func (s *Store) loadTenantLimits(ctx context.Context, tenantID string) (models.TenantLimits, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, max_total_scan_jobs, max_active_scan_jobs, max_scan_jobs_per_minute, max_scan_targets, max_ingestion_sources, updated_by, updated_at
		FROM tenant_limits
		WHERE tenant_id = $1
	`, strings.TrimSpace(tenantID))

	limits, err := scanTenantLimits(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.TenantLimits{
				TenantID: strings.TrimSpace(tenantID),
			}, nil
		}
		return models.TenantLimits{}, fmt.Errorf("load tenant limits: %w", err)
	}

	return limits, nil
}

func loadTenantLimitsTx(ctx context.Context, tx pgx.Tx, tenantID string) (models.TenantLimits, error) {
	row := tx.QueryRow(ctx, `
		SELECT tenant_id, max_total_scan_jobs, max_active_scan_jobs, max_scan_jobs_per_minute, max_scan_targets, max_ingestion_sources, updated_by, updated_at
		FROM tenant_limits
		WHERE tenant_id = $1
	`, strings.TrimSpace(tenantID))

	limits, err := scanTenantLimits(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.TenantLimits{
				TenantID: strings.TrimSpace(tenantID),
			}, nil
		}
		return models.TenantLimits{}, fmt.Errorf("load tenant limits tx: %w", err)
	}

	return limits, nil
}

func scanTenantLimits(row interface{ Scan(dest ...any) error }) (models.TenantLimits, error) {
	var limits models.TenantLimits
	err := row.Scan(
		&limits.TenantID,
		&limits.MaxTotalScanJobs,
		&limits.MaxActiveScanJobs,
		&limits.MaxScanJobsPerMinute,
		&limits.MaxScanTargets,
		&limits.MaxIngestionSources,
		&limits.UpdatedBy,
		&limits.UpdatedAt,
	)
	if err != nil {
		return models.TenantLimits{}, err
	}
	return limits, nil
}

func (s *Store) publishPlatformEvent(ctx context.Context, event models.PlatformEvent) error {
	event = normalizePlatformEvent(event)
	payloadJSON, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("marshal platform event payload: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO platform_events (
			id, tenant_id, event_type, source_service, aggregate_type, aggregate_id, payload_json, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
	`, event.ID, event.TenantID, event.EventType, event.SourceService, event.AggregateType, event.AggregateID, payloadJSON, event.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert platform event: %w", err)
	}

	return nil
}

func publishPlatformEventTx(ctx context.Context, tx pgx.Tx, event models.PlatformEvent) error {
	event = normalizePlatformEvent(event)
	payloadJSON, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("marshal platform event payload tx: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO platform_events (
			id, tenant_id, event_type, source_service, aggregate_type, aggregate_id, payload_json, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
	`, event.ID, event.TenantID, event.EventType, event.SourceService, event.AggregateType, event.AggregateID, payloadJSON, event.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert platform event tx: %w", err)
	}

	return nil
}

func normalizePlatformEvent(event models.PlatformEvent) models.PlatformEvent {
	now := time.Now().UTC()
	if strings.TrimSpace(event.ID) == "" {
		event.ID = nextPlatformEventID()
	}
	event.TenantID = strings.TrimSpace(event.TenantID)
	event.EventType = strings.TrimSpace(strings.ToLower(event.EventType))
	event.SourceService = strings.TrimSpace(event.SourceService)
	event.AggregateType = strings.TrimSpace(event.AggregateType)
	event.AggregateID = strings.TrimSpace(event.AggregateID)
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = now
	}
	return event
}

func scanPlatformEvent(row interface{ Scan(dest ...any) error }) (models.PlatformEvent, error) {
	var (
		event       models.PlatformEvent
		payloadJSON []byte
	)

	err := row.Scan(
		&event.ID,
		&event.TenantID,
		&event.EventType,
		&event.SourceService,
		&event.AggregateType,
		&event.AggregateID,
		&payloadJSON,
		&event.CreatedAt,
	)
	if err != nil {
		return models.PlatformEvent{}, err
	}

	if len(payloadJSON) > 0 {
		if err := json.Unmarshal(payloadJSON, &event.Payload); err != nil {
			return models.PlatformEvent{}, fmt.Errorf("decode platform event payload: %w", err)
		}
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}

	return event, nil
}

func nextPlatformEventID() string {
	sequence := atomic.AddUint64(&platformEventSequence, 1)
	return fmt.Sprintf("platform-event-%d-%06d", time.Now().UTC().Unix(), sequence)
}
