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

func (s *Store) CreateJob(ctx context.Context, tenantID string, actor string, request models.EnqueuePlatformJobRequest) (models.PlatformJob, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.PlatformJob{}, fmt.Errorf("begin create job tx: %w", err)
	}
	defer tx.Rollback(ctx)

	job, err := s.createJobTx(ctx, tx, tenantID, actor, request)
	if err != nil {
		return models.PlatformJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.PlatformJob{}, fmt.Errorf("commit create job tx: %w", err)
	}
	return job, nil
}

func (s *Store) createJobTx(ctx context.Context, tx pgx.Tx, tenantID string, actor string, request models.EnqueuePlatformJobRequest) (models.PlatformJob, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	jobKind := normalizeJobKind(request.JobKind)
	if jobKind == "" {
		return models.PlatformJob{}, errors.New("job kind is required")
	}

	connectorID := strings.TrimSpace(request.ConnectorID)
	var connector *models.Connector
	if connectorID != "" {
		loaded, found, loadErr := s.loadConnectorTx(ctx, tx, normalizedTenantID, connectorID)
		if loadErr != nil {
			return models.PlatformJob{}, loadErr
		}
		if !found {
			return models.PlatformJob{}, fmt.Errorf("connector %q not found in tenant %q", connectorID, normalizedTenantID)
		}
		connector = &loaded
	}

	now := time.Now().UTC()
	nextAttemptAt := now
	if request.NotBefore != nil && request.NotBefore.After(now) {
		nextAttemptAt = request.NotBefore.UTC()
	}

	job := models.PlatformJob{
		ID:            nextID("platform-job"),
		TenantID:      normalizedTenantID,
		JobKind:       jobKind,
		Payload:       cloneAnyMap(request.Payload),
		Status:        models.JobStatusQueued,
		AttemptCount:  0,
		NextAttemptAt: nextAttemptAt,
		CreatedBy:     normalizeActor(actor),
		CreatedAt:     now,
		UpdatedAt:     now,
		Connector:     connector,
	}
	if connector != nil {
		job.ConnectorID = connector.ID
	}

	_, err := tx.Exec(ctx, `
		INSERT INTO ps_platform_jobs (
			id, tenant_id, job_kind, connector_id, payload_json,
			status, attempt_count, next_attempt_at,
			last_error, last_response_status, last_response_body,
			leased_by, lease_expires_at, created_by, created_at, updated_at, completed_at
		) VALUES (
			$1, $2, $3, $4, $5::jsonb,
			$6, $7, $8,
			'', 0, '',
			'', NULL, $9, $10, $11, NULL
		)
	`,
		job.ID,
		job.TenantID,
		job.JobKind,
		nullIfEmpty(job.ConnectorID),
		marshalAnyMap(job.Payload),
		job.Status,
		job.AttemptCount,
		job.NextAttemptAt,
		job.CreatedBy,
		job.CreatedAt,
		job.UpdatedAt,
	)
	if err != nil {
		return models.PlatformJob{}, fmt.Errorf("insert job: %w", err)
	}

	return job, nil
}

func (s *Store) ListJobs(ctx context.Context, tenantID string, status string, kind string, limit int) ([]models.PlatformJob, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	normalizedStatus := normalizeStatus(status)
	normalizedKind := normalizeJobKind(kind)
	normalizedLimit := normalizeLimit(limit, defaultListLimit)

	query := `
		SELECT
			id, tenant_id, job_kind, connector_id, payload_json,
			status, attempt_count, next_attempt_at, last_error,
			last_response_status, last_response_body, leased_by, lease_expires_at,
			created_by, created_at, updated_at, completed_at
		FROM ps_platform_jobs
		WHERE tenant_id = $1
	`

	args := []any{normalizedTenantID}
	if normalizedStatus != "" {
		query += " AND status = $2"
		args = append(args, normalizedStatus)
		if normalizedKind != "" {
			query += " AND job_kind = $3 ORDER BY updated_at DESC LIMIT $4"
			args = append(args, normalizedKind, normalizedLimit)
		} else {
			query += " ORDER BY updated_at DESC LIMIT $3"
			args = append(args, normalizedLimit)
		}
	} else if normalizedKind != "" {
		query += " AND job_kind = $2 ORDER BY updated_at DESC LIMIT $3"
		args = append(args, normalizedKind, normalizedLimit)
	} else {
		query += " ORDER BY updated_at DESC LIMIT $2"
		args = append(args, normalizedLimit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	defer rows.Close()

	items := make([]models.PlatformJob, 0, normalizedLimit)
	for rows.Next() {
		job, scanErr := scanJob(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		if err := s.attachConnector(ctx, &job); err != nil {
			return nil, err
		}
		items = append(items, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate jobs: %w", err)
	}
	return items, nil
}

func (s *Store) GetJob(ctx context.Context, tenantID string, jobID string) (models.PlatformJob, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT
			id, tenant_id, job_kind, connector_id, payload_json,
			status, attempt_count, next_attempt_at, last_error,
			last_response_status, last_response_body, leased_by, lease_expires_at,
			created_by, created_at, updated_at, completed_at
		FROM ps_platform_jobs
		WHERE tenant_id = $1 AND id = $2
	`,
		s.ResolveTenantID(tenantID),
		strings.TrimSpace(jobID),
	)
	job, err := scanJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.PlatformJob{}, false, nil
		}
		return models.PlatformJob{}, false, err
	}
	if attachErr := s.attachConnector(ctx, &job); attachErr != nil {
		return models.PlatformJob{}, false, attachErr
	}
	return job, true, nil
}

func (s *Store) RetryJob(ctx context.Context, tenantID string, jobID string, actor string) (models.PlatformJob, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.PlatformJob{}, false, fmt.Errorf("begin retry job tx: %w", err)
	}
	defer tx.Rollback(ctx)

	job, found, err := s.loadJobForUpdateTx(ctx, tx, s.ResolveTenantID(tenantID), strings.TrimSpace(jobID))
	if err != nil {
		return models.PlatformJob{}, false, err
	}
	if !found {
		return models.PlatformJob{}, false, nil
	}

	if job.Status == models.JobStatusRunning {
		return job, true, nil
	}

	now := time.Now().UTC()
	job.Status = models.JobStatusQueued
	job.NextAttemptAt = now
	job.LeasedBy = ""
	job.LeaseExpiresAt = nil
	job.LastError = ""
	job.LastResponseBody = ""
	job.LastResponseStatus = 0
	job.CompletedAt = nil
	job.UpdatedAt = now
	job.CreatedBy = normalizeActor(actor)

	_, err = tx.Exec(ctx, `
		UPDATE ps_platform_jobs
		SET
			status = $3,
			next_attempt_at = $4,
			leased_by = '',
			lease_expires_at = NULL,
			last_error = '',
			last_response_status = 0,
			last_response_body = '',
			completed_at = NULL,
			updated_at = $5
		WHERE tenant_id = $1 AND id = $2
	`,
		job.TenantID,
		job.ID,
		job.Status,
		job.NextAttemptAt,
		job.UpdatedAt,
	)
	if err != nil {
		return models.PlatformJob{}, false, fmt.Errorf("retry update job: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.PlatformJob{}, false, fmt.Errorf("commit retry job tx: %w", err)
	}

	final, _, err := s.GetJob(ctx, job.TenantID, job.ID)
	return final, true, err
}

func (s *Store) LeaseJobs(ctx context.Context, workerID string, leaseTTL time.Duration, batch int) ([]models.PlatformJob, error) {
	normalizedWorkerID := strings.TrimSpace(workerID)
	if normalizedWorkerID == "" {
		normalizedWorkerID = "platform-worker"
	}
	if leaseTTL <= 0 {
		leaseTTL = 45 * time.Second
	}

	normalizedBatch := clampInt(batch, 1, 256, 32)
	now := time.Now().UTC()
	leaseExpiresAt := now.Add(leaseTTL)

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin lease jobs tx: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT
			id, tenant_id, job_kind, connector_id, payload_json,
			status, attempt_count, next_attempt_at, last_error,
			last_response_status, last_response_body, leased_by, lease_expires_at,
			created_by, created_at, updated_at, completed_at
		FROM ps_platform_jobs
		WHERE status IN ($1, $2)
			AND next_attempt_at <= $3
			AND (lease_expires_at IS NULL OR lease_expires_at <= $3)
		ORDER BY next_attempt_at ASC, created_at ASC
		LIMIT $4
		FOR UPDATE SKIP LOCKED
	`,
		models.JobStatusQueued,
		models.JobStatusRetrying,
		now,
		normalizedBatch,
	)
	if err != nil {
		return nil, fmt.Errorf("select leaseable jobs: %w", err)
	}

	jobs := make([]models.PlatformJob, 0, normalizedBatch)
	for rows.Next() {
		job, scanErr := scanJob(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		jobs = append(jobs, job)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate leaseable jobs: %w", err)
	}

	for index := range jobs {
		jobs[index].Status = models.JobStatusRunning
		jobs[index].LeasedBy = normalizedWorkerID
		jobs[index].LeaseExpiresAt = &leaseExpiresAt
		jobs[index].UpdatedAt = now

		_, err := tx.Exec(ctx, `
			UPDATE ps_platform_jobs
			SET
				status = $3,
				leased_by = $4,
				lease_expires_at = $5,
				updated_at = $6
			WHERE id = $1 AND tenant_id = $2
		`,
			jobs[index].ID,
			jobs[index].TenantID,
			jobs[index].Status,
			jobs[index].LeasedBy,
			jobs[index].LeaseExpiresAt,
			jobs[index].UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("update leased job %s: %w", jobs[index].ID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit lease jobs tx: %w", err)
	}

	for index := range jobs {
		if attachErr := s.attachConnector(ctx, &jobs[index]); attachErr != nil {
			return nil, attachErr
		}
	}
	return jobs, nil
}

func (s *Store) FinalizeJob(ctx context.Context, workerID string, request models.FinalizePlatformJobRequest) (models.PlatformJob, bool, error) {
	jobID := strings.TrimSpace(request.JobID)
	if jobID == "" {
		return models.PlatformJob{}, false, errors.New("job id is required")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.PlatformJob{}, false, fmt.Errorf("begin finalize job tx: %w", err)
	}
	defer tx.Rollback(ctx)

	job, found, err := s.loadJobForUpdateTx(ctx, tx, "", jobID)
	if err != nil {
		return models.PlatformJob{}, false, err
	}
	if !found {
		return models.PlatformJob{}, false, nil
	}

	now := time.Now().UTC()
	attemptNumber := job.AttemptCount + 1
	responseBody := truncateString(strings.TrimSpace(request.ResponseBody), maxResponseBodyBytes)
	errorMessage := truncateString(strings.TrimSpace(request.ErrorMessage), maxResponseBodyBytes)

	_, err = tx.Exec(ctx, `
		INSERT INTO ps_platform_job_attempts (
			id, job_id, tenant_id, connector_id, worker_id,
			success, response_status, response_body, error_message, duration_ms, attempted_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10, $11, $12
		)
	`,
		nextID("platform-attempt"),
		job.ID,
		job.TenantID,
		nullIfEmpty(job.ConnectorID),
		strings.TrimSpace(workerID),
		request.Success,
		request.ResponseStatus,
		responseBody,
		errorMessage,
		request.DurationMs,
		now,
		now,
	)
	if err != nil {
		return models.PlatformJob{}, false, fmt.Errorf("insert job attempt: %w", err)
	}

	connectorPolicy := models.Connector{
		RetryMaxAttempts:      defaultRetryAttempts,
		RetryBaseDelaySeconds: defaultRetryBaseSecs,
		RetryMaxDelaySeconds:  defaultRetryMaxSecs,
	}
	if connectorID := strings.TrimSpace(job.ConnectorID); connectorID != "" {
		connector, foundConnector, connectorErr := s.loadConnectorTx(ctx, tx, job.TenantID, connectorID)
		if connectorErr != nil {
			return models.PlatformJob{}, false, connectorErr
		}
		if foundConnector {
			connectorPolicy = connector
		}
	}

	nextStatus := models.JobStatusSucceeded
	nextAttemptAt := now
	lastError := ""
	var completedAt *time.Time = &now

	if !request.Success {
		nextStatus = models.JobStatusDeadLetter
		lastError = errorMessage
		completedAt = &now

		if shouldRetryJob(attemptNumber, connectorPolicy.RetryMaxAttempts, request.ResponseStatus, errorMessage) {
			delay := computeRetryDelay(attemptNumber, connectorPolicy.RetryBaseDelaySeconds, connectorPolicy.RetryMaxDelaySeconds)
			nextStatus = models.JobStatusRetrying
			nextAttemptAt = now.Add(delay)
			completedAt = nil
		}
	}

	_, err = tx.Exec(ctx, `
		UPDATE ps_platform_jobs
		SET
			status = $3,
			attempt_count = $4,
			next_attempt_at = $5,
			last_error = $6,
			last_response_status = $7,
			last_response_body = $8,
			leased_by = '',
			lease_expires_at = NULL,
			updated_at = $9,
			completed_at = $10
		WHERE tenant_id = $1 AND id = $2
	`,
		job.TenantID,
		job.ID,
		nextStatus,
		attemptNumber,
		nextAttemptAt,
		lastError,
		request.ResponseStatus,
		responseBody,
		now,
		completedAt,
	)
	if err != nil {
		return models.PlatformJob{}, false, fmt.Errorf("update finalized job: %w", err)
	}

	job.Status = nextStatus
	job.AttemptCount = attemptNumber
	job.NextAttemptAt = nextAttemptAt
	job.LastError = lastError
	job.LastResponseStatus = request.ResponseStatus
	job.LastResponseBody = responseBody
	job.LeasedBy = ""
	job.LeaseExpiresAt = nil
	job.UpdatedAt = now
	job.CompletedAt = completedAt

	if sideEffectErr := s.applyJobSideEffectsTx(ctx, tx, job, responseBody); sideEffectErr != nil {
		return models.PlatformJob{}, false, sideEffectErr
	}

	if err := tx.Commit(ctx); err != nil {
		return models.PlatformJob{}, false, fmt.Errorf("commit finalize job tx: %w", err)
	}

	final, foundFinal, err := s.GetJob(ctx, job.TenantID, job.ID)
	if err != nil {
		return models.PlatformJob{}, false, err
	}
	if foundFinal {
		return final, true, nil
	}
	return job, true, nil
}

func (s *Store) applyJobSideEffectsTx(ctx context.Context, tx pgx.Tx, job models.PlatformJob, responseBody string) error {
	payload := cloneAnyMap(job.Payload)
	notificationID := extractString(payload, "notification_id")
	auditExportID := extractString(payload, "audit_export_id")
	syncRunID := extractString(payload, "sync_run_id")

	now := time.Now().UTC()

	switch job.Status {
	case models.JobStatusSucceeded:
		if notificationID != "" {
			if _, err := tx.Exec(ctx, `
				UPDATE ps_notifications
				SET status = $3
				WHERE tenant_id = $1 AND id = $2
			`, job.TenantID, notificationID, models.NotificationStatusSent); err != nil {
				return fmt.Errorf("update notification success status: %w", err)
			}
		}
		if auditExportID != "" {
			fileRef := extractString(parseJSONMap(responseBody), "file_ref")
			if _, err := tx.Exec(ctx, `
				UPDATE ps_audit_exports
				SET
					status = $3,
					completed_at = $4,
					file_ref = $5,
					error_message = ''
				WHERE tenant_id = $1 AND id = $2
			`, job.TenantID, auditExportID, models.AuditExportStatusCompleted, now, fileRef); err != nil {
				return fmt.Errorf("update audit export success status: %w", err)
			}
		}
		if syncRunID != "" {
			if _, err := tx.Exec(ctx, `
				UPDATE ps_sync_runs
				SET
					status = $3,
					completed_at = $4,
					summary_json = $5::jsonb,
					error_message = ''
				WHERE tenant_id = $1 AND id = $2
			`, job.TenantID, syncRunID, models.SyncStatusCompleted, now, marshalAnyMap(parseJSONMap(responseBody))); err != nil {
				return fmt.Errorf("update sync run success status: %w", err)
			}
		}
	case models.JobStatusDeadLetter:
		if notificationID != "" {
			if _, err := tx.Exec(ctx, `
				UPDATE ps_notifications
				SET status = $3
				WHERE tenant_id = $1 AND id = $2
			`, job.TenantID, notificationID, models.NotificationStatusFailed); err != nil {
				return fmt.Errorf("update notification failed status: %w", err)
			}
		}
		if auditExportID != "" {
			if _, err := tx.Exec(ctx, `
				UPDATE ps_audit_exports
				SET
					status = $3,
					completed_at = $4,
					error_message = $5
				WHERE tenant_id = $1 AND id = $2
			`, job.TenantID, auditExportID, models.AuditExportStatusFailed, now, truncateString(job.LastError, maxResponseBodyBytes)); err != nil {
				return fmt.Errorf("update audit export failed status: %w", err)
			}
		}
		if syncRunID != "" {
			if _, err := tx.Exec(ctx, `
				UPDATE ps_sync_runs
				SET
					status = $3,
					completed_at = $4,
					error_message = $5
				WHERE tenant_id = $1 AND id = $2
			`, job.TenantID, syncRunID, models.SyncStatusFailed, now, truncateString(job.LastError, maxResponseBodyBytes)); err != nil {
				return fmt.Errorf("update sync run failed status: %w", err)
			}
		}
	}

	return nil
}

func (s *Store) loadJobForUpdateTx(ctx context.Context, tx pgx.Tx, tenantID string, jobID string) (models.PlatformJob, bool, error) {
	query := `
		SELECT
			id, tenant_id, job_kind, connector_id, payload_json,
			status, attempt_count, next_attempt_at, last_error,
			last_response_status, last_response_body, leased_by, lease_expires_at,
			created_by, created_at, updated_at, completed_at
		FROM ps_platform_jobs
		WHERE id = $1
	`
	args := []any{jobID}
	if strings.TrimSpace(tenantID) != "" {
		query += " AND tenant_id = $2"
		args = append(args, tenantID)
	}
	query += " FOR UPDATE"

	row := tx.QueryRow(ctx, query, args...)
	job, err := scanJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.PlatformJob{}, false, nil
		}
		return models.PlatformJob{}, false, err
	}
	return job, true, nil
}

func (s *Store) attachConnector(ctx context.Context, job *models.PlatformJob) error {
	if job == nil {
		return nil
	}
	connectorID := strings.TrimSpace(job.ConnectorID)
	if connectorID == "" {
		job.Connector = nil
		return nil
	}
	connector, found, err := s.loadConnector(ctx, job.TenantID, connectorID)
	if err != nil {
		return err
	}
	if !found {
		job.Connector = nil
		return nil
	}
	job.Connector = &connector
	return nil
}
