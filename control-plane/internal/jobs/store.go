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
	"github.com/jackc/pgx/v5/pgxpool"

	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/database"
	"unifiedsecurityscanner/control-plane/internal/models"
)

var (
	jobSequence            uint64
	leaseSequence          uint64
	ErrWorkerLeaseNotFound = errors.New("worker lease not found")
)

type Store struct {
	pool               *pgxpool.Pool
	workerHeartbeatTTL time.Duration
}

func NewStore(ctx context.Context, cfg config.Config) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	poolConfig.MaxConns = cfg.DatabaseMaxConns
	poolConfig.MinConns = cfg.DatabaseMinConns
	poolConfig.MaxConnLifetime = cfg.DatabaseConnTTL

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	if err := database.Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}

	return &Store{
		pool:               pool,
		workerHeartbeatTTL: cfg.WorkerHeartbeatTTL,
	}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *Store) Create(ctx context.Context, request models.CreateScanJobRequest) (models.ScanJob, error) {
	now := time.Now().UTC()
	tools := sanitizeTools(request.Tools)
	if len(tools) == 0 {
		tools = []string{"semgrep", "trivy", "zap"}
	}

	job := models.ScanJob{
		ID:           nextJobID(),
		TenantID:     strings.TrimSpace(request.TenantID),
		TargetKind:   strings.TrimSpace(request.TargetKind),
		Target:       strings.TrimSpace(request.Target),
		Profile:      strings.TrimSpace(request.Profile),
		RequestedBy:  strings.TrimSpace(request.RequestedBy),
		Tools:        tools,
		ApprovalMode: approvalModeForTools(tools),
		Status:       models.ScanJobStatusQueued,
		RequestedAt:  now,
		UpdatedAt:    now,
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_jobs (
			id, tenant_id, target_kind, target, profile, requested_by,
			tools, approval_mode, status, requested_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11
		)
	`, job.ID, job.TenantID, job.TargetKind, job.Target, job.Profile, job.RequestedBy,
		job.Tools, job.ApprovalMode, string(job.Status), job.RequestedAt, job.UpdatedAt)
	if err != nil {
		return models.ScanJob{}, fmt.Errorf("insert scan job: %w", err)
	}

	return job, nil
}

func (s *Store) Get(ctx context.Context, id string) (models.ScanJob, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, target_kind, target, profile, requested_by,
		       tools, approval_mode, status, requested_at, updated_at
		FROM scan_jobs
		WHERE id = $1
	`, strings.TrimSpace(id))

	job, err := scanJobFromRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ScanJob{}, false, nil
		}

		return models.ScanJob{}, false, fmt.Errorf("select scan job: %w", err)
	}

	return job, true, nil
}

func (s *Store) List(ctx context.Context, limit int) ([]models.ScanJob, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, target_kind, target, profile, requested_by,
		       tools, approval_mode, status, requested_at, updated_at
		FROM scan_jobs
		ORDER BY requested_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list scan jobs: %w", err)
	}
	defer rows.Close()

	out := make([]models.ScanJob, 0, limit)
	for rows.Next() {
		job, err := scanJobFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan jobs: %w", err)
	}

	return out, nil
}

func (s *Store) RegisterWorker(ctx context.Context, request models.WorkerRegistrationRequest) (models.WorkerRegistrationResponse, error) {
	now := time.Now().UTC()
	leaseID := nextLeaseID()
	heartbeatIntervalSeconds := int64((s.workerHeartbeatTTL / 2).Seconds())
	if heartbeatIntervalSeconds < 10 {
		heartbeatIntervalSeconds = 10
	}

	capabilitiesJSON, err := json.Marshal(request.Capabilities)
	if err != nil {
		return models.WorkerRegistrationResponse{}, fmt.Errorf("marshal capabilities: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO workers (
			worker_id, lease_id, worker_version, operating_system, hostname,
			capabilities_json, metrics_json, heartbeat_interval_seconds,
			last_heartbeat_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, '{}'::jsonb, $7,
			$8, $8
		)
		ON CONFLICT (worker_id) DO UPDATE SET
			lease_id = EXCLUDED.lease_id,
			worker_version = EXCLUDED.worker_version,
			operating_system = EXCLUDED.operating_system,
			hostname = EXCLUDED.hostname,
			capabilities_json = EXCLUDED.capabilities_json,
			heartbeat_interval_seconds = EXCLUDED.heartbeat_interval_seconds,
			last_heartbeat_at = EXCLUDED.last_heartbeat_at,
			updated_at = EXCLUDED.updated_at
	`, request.WorkerID, leaseID, request.WorkerVersion, request.OperatingSystem, request.Hostname,
		capabilitiesJSON, heartbeatIntervalSeconds, now)
	if err != nil {
		return models.WorkerRegistrationResponse{}, fmt.Errorf("register worker: %w", err)
	}

	return models.WorkerRegistrationResponse{
		Accepted:                 true,
		LeaseID:                  leaseID,
		HeartbeatIntervalSeconds: heartbeatIntervalSeconds,
	}, nil
}

func (s *Store) RecordHeartbeat(ctx context.Context, request models.HeartbeatRequest) (models.HeartbeatResponse, error) {
	metricsJSON, err := json.Marshal(request.Metrics)
	if err != nil {
		return models.HeartbeatResponse{}, fmt.Errorf("marshal metrics: %w", err)
	}

	now := time.Now().UTC()
	result, err := s.pool.Exec(ctx, `
		UPDATE workers
		SET metrics_json = $1,
		    last_heartbeat_at = $2,
		    updated_at = $2
		WHERE worker_id = $3 AND lease_id = $4
	`, metricsJSON, now, request.WorkerID, request.LeaseID)
	if err != nil {
		return models.HeartbeatResponse{}, fmt.Errorf("record heartbeat: %w", err)
	}

	if result.RowsAffected() == 0 {
		return models.HeartbeatResponse{}, ErrWorkerLeaseNotFound
	}

	return models.HeartbeatResponse{
		Assignments: make([]models.JobAssignment, 0),
	}, nil
}

func scanJobFromRow(row pgx.Row) (models.ScanJob, error) {
	var job models.ScanJob
	var status string
	err := row.Scan(
		&job.ID,
		&job.TenantID,
		&job.TargetKind,
		&job.Target,
		&job.Profile,
		&job.RequestedBy,
		&job.Tools,
		&job.ApprovalMode,
		&status,
		&job.RequestedAt,
		&job.UpdatedAt,
	)
	job.Status = models.ScanJobStatus(status)
	return job, err
}

func scanJobFromRows(rows pgx.Rows) (models.ScanJob, error) {
	var job models.ScanJob
	var status string
	err := rows.Scan(
		&job.ID,
		&job.TenantID,
		&job.TargetKind,
		&job.Target,
		&job.Profile,
		&job.RequestedBy,
		&job.Tools,
		&job.ApprovalMode,
		&status,
		&job.RequestedAt,
		&job.UpdatedAt,
	)
	if err != nil {
		return models.ScanJob{}, fmt.Errorf("scan scan job row: %w", err)
	}

	job.Status = models.ScanJobStatus(status)
	return job, nil
}

func nextJobID() string {
	sequence := atomic.AddUint64(&jobSequence, 1)
	return fmt.Sprintf("job-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextLeaseID() string {
	sequence := atomic.AddUint64(&leaseSequence, 1)
	return fmt.Sprintf("lease-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func sanitizeTools(tools []string) []string {
	seen := make(map[string]struct{}, len(tools))
	out := make([]string, 0, len(tools))

	for _, tool := range tools {
		normalized := strings.ToLower(strings.TrimSpace(tool))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}

		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}

	return out
}

func approvalModeForTools(tools []string) string {
	for _, tool := range tools {
		switch tool {
		case "metasploit", "sqlmap", "nmap", "nuclei", "zap":
			return "policy-gated"
		}
	}

	return "standard"
}
