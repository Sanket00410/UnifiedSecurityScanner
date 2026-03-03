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
	taskSequence           uint64
	policySequence         uint64
	remediationSequence    uint64
	ErrWorkerLeaseNotFound = errors.New("worker lease not found")
	ErrTaskNotFound        = errors.New("task not found")
	ErrProtectedToken      = errors.New("protected token")
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

	store := &Store{
		pool:               pool,
		workerHeartbeatTTL: cfg.WorkerHeartbeatTTL,
	}

	if err := store.EnsureBootstrap(ctx, cfg); err != nil {
		pool.Close()
		return nil, err
	}

	return store, nil
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
		tools = defaultToolsForTargetKind(request.TargetKind)
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

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.ScanJob{}, fmt.Errorf("begin create job tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO scan_jobs (
			id, tenant_id, target_kind, target, profile, requested_by,
			tools, approval_mode, status, requested_at, updated_at, running_task_count
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, 0
		)
	`, job.ID, job.TenantID, job.TargetKind, job.Target, job.Profile, job.RequestedBy,
		job.Tools, job.ApprovalMode, string(job.Status), job.RequestedAt, job.UpdatedAt)
	if err != nil {
		return models.ScanJob{}, fmt.Errorf("insert scan job: %w", err)
	}

	for _, tool := range tools {
		taskID := nextTaskID()
		labelsJSON, err := json.Marshal(map[string]string{
			"scan_job_id": job.ID,
			"profile":     job.Profile,
		})
		if err != nil {
			return models.ScanJob{}, fmt.Errorf("marshal task labels: %w", err)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO scan_job_tasks (
				id, scan_job_id, tenant_id, adapter_id, target_kind, target,
				status, approved_modules, labels_json, max_runtime_seconds,
				evidence_upload_url, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10,
				$11, $12, $12
			)
		`, taskID, job.ID, job.TenantID, tool, job.TargetKind, job.Target,
			string(models.TaskStatusQueued), approvedModulesForTool(tool, job.TargetKind), labelsJSON, maxRuntimeForTool(tool),
			fmt.Sprintf("local://evidence/%s", taskID), now)
		if err != nil {
			return models.ScanJob{}, fmt.Errorf("insert scan job task: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return models.ScanJob{}, fmt.Errorf("commit create job tx: %w", err)
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
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.HeartbeatResponse{}, fmt.Errorf("begin heartbeat tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	metricsJSON, err := json.Marshal(request.Metrics)
	if err != nil {
		return models.HeartbeatResponse{}, fmt.Errorf("marshal metrics: %w", err)
	}

	now := time.Now().UTC()
	var capabilitiesJSON []byte
	err = tx.QueryRow(ctx, `
		UPDATE workers
		SET metrics_json = $1,
		    last_heartbeat_at = $2,
		    updated_at = $2
		WHERE worker_id = $3 AND lease_id = $4
		RETURNING capabilities_json
	`, metricsJSON, now, request.WorkerID, request.LeaseID).Scan(&capabilitiesJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.HeartbeatResponse{}, ErrWorkerLeaseNotFound
		}
		return models.HeartbeatResponse{}, fmt.Errorf("record heartbeat: %w", err)
	}

	assignments, err := claimAssignmentsTx(ctx, tx, request.WorkerID, request.LeaseID, capabilitiesJSON, now, 3)
	if err != nil {
		return models.HeartbeatResponse{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.HeartbeatResponse{}, fmt.Errorf("commit heartbeat tx: %w", err)
	}

	return models.HeartbeatResponse{Assignments: assignments}, nil
}

func (s *Store) RecordTaskStatus(ctx context.Context, workerID string, taskID string, state models.TaskStatus) error {
	commandTag, err := s.pool.Exec(ctx, `
		UPDATE scan_job_tasks
		SET status = $1,
		    updated_at = $2
		WHERE id = $3 AND assigned_worker_id = $4
	`, string(state), time.Now().UTC(), strings.TrimSpace(taskID), strings.TrimSpace(workerID))
	if err != nil {
		return fmt.Errorf("update task status: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrTaskNotFound
	}

	return nil
}

func (s *Store) GetTaskContext(ctx context.Context, taskID string) (models.TaskContext, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT t.id, t.scan_job_id, t.tenant_id, t.adapter_id, t.target_kind, t.target
		FROM scan_job_tasks t
		WHERE t.id = $1
	`, strings.TrimSpace(taskID))

	var task models.TaskContext
	err := row.Scan(&task.TaskID, &task.ScanJobID, &task.TenantID, &task.AdapterID, &task.TargetKind, &task.Target)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.TaskContext{}, ErrTaskNotFound
		}
		return models.TaskContext{}, fmt.Errorf("get task context: %w", err)
	}

	return task, nil
}

func (s *Store) FinalizeTask(ctx context.Context, submission models.TaskResultSubmission) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin finalize task tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var task models.TaskContext
	err = tx.QueryRow(ctx, `
		SELECT id, scan_job_id, tenant_id, adapter_id, target_kind, target
		FROM scan_job_tasks
		WHERE id = $1
	`, strings.TrimSpace(submission.TaskID)).Scan(
		&task.TaskID,
		&task.ScanJobID,
		&task.TenantID,
		&task.AdapterID,
		&task.TargetKind,
		&task.Target,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTaskNotFound
		}
		return fmt.Errorf("load task for finalize: %w", err)
	}

	now := time.Now().UTC()
	finalStatus := normalizeTaskState(submission.FinalState)

	_, err = tx.Exec(ctx, `
		UPDATE scan_job_tasks
		SET status = $1,
		    updated_at = $2
		WHERE id = $3
	`, string(finalStatus), now, submission.TaskID)
	if err != nil {
		return fmt.Errorf("finalize task: %w", err)
	}

	for _, finding := range submission.ReportedFindings {
		payload, err := json.Marshal(finding)
		if err != nil {
			return fmt.Errorf("marshal normalized finding: %w", err)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO normalized_findings (
				finding_id, scan_job_id, task_id, tenant_id, adapter_id, finding_json, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $7
			)
			ON CONFLICT (finding_id) DO UPDATE SET
				finding_json = EXCLUDED.finding_json,
				updated_at = EXCLUDED.updated_at
		`, finding.FindingID, task.ScanJobID, submission.TaskID, task.TenantID, task.AdapterID, payload, now)
		if err != nil {
			return fmt.Errorf("insert normalized finding: %w", err)
		}
	}

	if err := recomputeScanJobStatusTx(ctx, tx, task.ScanJobID, now); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit finalize task tx: %w", err)
	}

	return nil
}

func (s *Store) ListFindings(ctx context.Context, limit int) ([]models.CanonicalFinding, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT finding_json
		FROM normalized_findings
		ORDER BY updated_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	out := make([]models.CanonicalFinding, 0, limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan normalized finding: %w", err)
		}

		var finding models.CanonicalFinding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return nil, fmt.Errorf("unmarshal normalized finding: %w", err)
		}

		out = append(out, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}

	return out, nil
}

func (s *Store) ListAssets(ctx context.Context, limit int) ([]models.AssetSummary, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			sj.target,
			sj.target_kind,
			MAX(sj.updated_at) AS last_scanned_at,
			COUNT(DISTINCT sj.id) AS scan_count,
			COUNT(nf.finding_id) AS finding_count
		FROM scan_jobs sj
		LEFT JOIN normalized_findings nf ON nf.scan_job_id = sj.id
		GROUP BY sj.target, sj.target_kind
		ORDER BY MAX(sj.updated_at) DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()

	out := make([]models.AssetSummary, 0, limit)
	for rows.Next() {
		var asset models.AssetSummary
		if err := rows.Scan(
			&asset.AssetID,
			&asset.AssetType,
			&asset.LastScannedAt,
			&asset.ScanCount,
			&asset.FindingCount,
		); err != nil {
			return nil, fmt.Errorf("scan asset summary: %w", err)
		}

		out = append(out, asset)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assets: %w", err)
	}

	return out, nil
}

func (s *Store) ListPolicies(ctx context.Context, limit int) ([]models.Policy, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, name, scope, mode, enabled, rules_json, updated_by, created_at, updated_at
		FROM policies
		ORDER BY updated_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	out := make([]models.Policy, 0, limit)
	for rows.Next() {
		var policy models.Policy
		var rulesJSON []byte

		if err := rows.Scan(
			&policy.ID,
			&policy.Name,
			&policy.Scope,
			&policy.Mode,
			&policy.Enabled,
			&rulesJSON,
			&policy.UpdatedBy,
			&policy.CreatedAt,
			&policy.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}

		if len(rulesJSON) > 0 {
			if err := json.Unmarshal(rulesJSON, &policy.Rules); err != nil {
				return nil, fmt.Errorf("unmarshal policy rules: %w", err)
			}
		}

		out = append(out, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policies: %w", err)
	}

	return out, nil
}

func (s *Store) CreatePolicy(ctx context.Context, request models.CreatePolicyRequest) (models.Policy, error) {
	now := time.Now().UTC()
	policy := models.Policy{
		ID:        nextPolicyID(),
		Name:      strings.TrimSpace(request.Name),
		Scope:     strings.TrimSpace(request.Scope),
		Mode:      strings.TrimSpace(request.Mode),
		Enabled:   request.Enabled,
		Rules:     sanitizeRuleList(request.Rules),
		UpdatedBy: strings.TrimSpace(request.UpdatedBy),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if policy.Scope == "" {
		policy.Scope = "global"
	}
	if policy.Mode == "" {
		policy.Mode = "monitor"
	}
	if policy.UpdatedBy == "" {
		policy.UpdatedBy = "system"
	}

	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return models.Policy{}, fmt.Errorf("marshal policy rules: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO policies (
			id, name, scope, mode, enabled, rules_json, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $8
		)
	`, policy.ID, policy.Name, policy.Scope, policy.Mode, policy.Enabled, rulesJSON, policy.UpdatedBy, now)
	if err != nil {
		return models.Policy{}, fmt.Errorf("insert policy: %w", err)
	}

	return policy, nil
}

func (s *Store) ListRemediations(ctx context.Context, limit int) ([]models.RemediationAction, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, finding_id, title, status, owner, due_at, notes, created_at, updated_at
		FROM remediation_actions
		ORDER BY updated_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list remediations: %w", err)
	}
	defer rows.Close()

	out := make([]models.RemediationAction, 0, limit)
	for rows.Next() {
		var item models.RemediationAction
		if err := rows.Scan(
			&item.ID,
			&item.FindingID,
			&item.Title,
			&item.Status,
			&item.Owner,
			&item.DueAt,
			&item.Notes,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan remediation: %w", err)
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate remediations: %w", err)
	}

	return out, nil
}

func (s *Store) CreateRemediation(ctx context.Context, request models.CreateRemediationRequest) (models.RemediationAction, error) {
	now := time.Now().UTC()
	item := models.RemediationAction{
		ID:        nextRemediationID(),
		FindingID: strings.TrimSpace(request.FindingID),
		Title:     strings.TrimSpace(request.Title),
		Status:    strings.TrimSpace(request.Status),
		Owner:     strings.TrimSpace(request.Owner),
		DueAt:     request.DueAt,
		Notes:     strings.TrimSpace(request.Notes),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if item.Status == "" {
		item.Status = "open"
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO remediation_actions (
			id, finding_id, title, status, owner, due_at, notes, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $8
		)
	`, item.ID, item.FindingID, item.Title, item.Status, item.Owner, item.DueAt, item.Notes, now)
	if err != nil {
		return models.RemediationAction{}, fmt.Errorf("insert remediation: %w", err)
	}

	return item, nil
}

func claimAssignmentsTx(
	ctx context.Context,
	tx pgx.Tx,
	workerID string,
	leaseID string,
	capabilitiesJSON []byte,
	now time.Time,
	limit int,
) ([]models.JobAssignment, error) {
	var capabilities []models.WorkerCapability
	if len(capabilitiesJSON) > 0 {
		if err := json.Unmarshal(capabilitiesJSON, &capabilities); err != nil {
			return nil, fmt.Errorf("unmarshal worker capabilities: %w", err)
		}
	}

	adapters := supportedAdapters(capabilities)
	if len(adapters) == 0 {
		return make([]models.JobAssignment, 0), nil
	}

	rows, err := tx.Query(ctx, `
		SELECT id, scan_job_id, tenant_id, adapter_id, target_kind, target,
		       approved_modules, labels_json, max_runtime_seconds, evidence_upload_url
		FROM scan_job_tasks
		WHERE status = 'queued'
		  AND adapter_id = ANY($1)
		ORDER BY created_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, adapters, limit)
	if err != nil {
		return nil, fmt.Errorf("claim task query: %w", err)
	}
	defer rows.Close()

	type queuedTask struct {
		taskID            string
		scanJobID         string
		tenantID          string
		adapterID         string
		targetKind        string
		target            string
		approvedModules   []string
		labels            map[string]string
		maxRuntimeSeconds int64
		evidenceUploadURL string
	}

	queued := make([]queuedTask, 0, limit)

	for rows.Next() {
		var task queuedTask
		var approvedModules []string
		var labelsJSON []byte

		if err := rows.Scan(
			&task.taskID,
			&task.scanJobID,
			&task.tenantID,
			&task.adapterID,
			&task.targetKind,
			&task.target,
			&approvedModules,
			&labelsJSON,
			&task.maxRuntimeSeconds,
			&task.evidenceUploadURL,
		); err != nil {
			return nil, fmt.Errorf("scan claimed task: %w", err)
		}

		task.labels = make(map[string]string)
		if len(labelsJSON) > 0 {
			if err := json.Unmarshal(labelsJSON, &task.labels); err != nil {
				return nil, fmt.Errorf("unmarshal task labels: %w", err)
			}
		}
		task.labels["scan_job_id"] = task.scanJobID
		task.approvedModules = approvedModules
		queued = append(queued, task)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed tasks: %w", err)
	}

	rows.Close()

	assignments := make([]models.JobAssignment, 0, len(queued))
	for _, task := range queued {
		_, err := tx.Exec(ctx, `
			UPDATE scan_job_tasks
			SET status = $1,
			    assigned_worker_id = $2,
			    lease_id = $3,
			    assigned_at = $4,
			    updated_at = $4
			WHERE id = $5
		`, string(models.TaskStatusRunning), workerID, leaseID, now, task.taskID)
		if err != nil {
			return nil, fmt.Errorf("update claimed task: %w", err)
		}

		_, err = tx.Exec(ctx, `
			UPDATE scan_jobs
			SET status = $1,
			    running_task_count = running_task_count + 1,
			    updated_at = $2
			WHERE id = $3
		`, string(models.ScanJobStatusRunning), now, task.scanJobID)
		if err != nil {
			return nil, fmt.Errorf("update parent scan job: %w", err)
		}

		assignments = append(assignments, models.JobAssignment{
			JobID:             task.taskID,
			TenantID:          task.tenantID,
			AdapterID:         task.adapterID,
			TargetKind:        task.targetKind,
			Target:            task.target,
			ExecutionMode:     executionModeForTool(task.adapterID),
			ApprovedModules:   task.approvedModules,
			Labels:            task.labels,
			MaxRuntimeSeconds: task.maxRuntimeSeconds,
			EvidenceUploadURL: task.evidenceUploadURL,
		})
	}

	return assignments, nil
}

func recomputeScanJobStatusTx(ctx context.Context, tx pgx.Tx, scanJobID string, now time.Time) error {
	var total, completed, failed, canceled int
	err := tx.QueryRow(ctx, `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE status = 'completed') AS completed,
			COUNT(*) FILTER (WHERE status = 'failed') AS failed,
			COUNT(*) FILTER (WHERE status = 'canceled') AS canceled
		FROM scan_job_tasks
		WHERE scan_job_id = $1
	`, scanJobID).Scan(&total, &completed, &failed, &canceled)
	if err != nil {
		return fmt.Errorf("query task aggregate: %w", err)
	}

	nextStatus := string(models.ScanJobStatusRunning)
	switch {
	case total == 0:
		nextStatus = string(models.ScanJobStatusQueued)
	case completed == total:
		nextStatus = string(models.ScanJobStatusCompleted)
	case failed+canceled > 0 && completed+failed+canceled == total:
		nextStatus = string(models.ScanJobStatusFailed)
	}

	runningCount := total - completed - failed - canceled
	if runningCount < 0 {
		runningCount = 0
	}

	_, err = tx.Exec(ctx, `
		UPDATE scan_jobs
		SET status = $1,
		    running_task_count = $2,
		    updated_at = $3
		WHERE id = $4
	`, nextStatus, runningCount, now, scanJobID)
	if err != nil {
		return fmt.Errorf("update recomputed scan job status: %w", err)
	}

	return nil
}

func normalizeTaskState(state string) models.TaskStatus {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "completed", "job_state_completed":
		return models.TaskStatusCompleted
	case "failed", "job_state_failed":
		return models.TaskStatusFailed
	case "canceled", "cancelled", "job_state_canceled":
		return models.TaskStatusCanceled
	case "running", "job_state_running":
		return models.TaskStatusRunning
	default:
		return models.TaskStatusFailed
	}
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

func nextTaskID() string {
	sequence := atomic.AddUint64(&taskSequence, 1)
	return fmt.Sprintf("task-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextPolicyID() string {
	sequence := atomic.AddUint64(&policySequence, 1)
	return fmt.Sprintf("policy-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextRemediationID() string {
	sequence := atomic.AddUint64(&remediationSequence, 1)
	return fmt.Sprintf("remediation-%d-%06d", time.Now().UTC().Unix(), sequence)
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

func sanitizeRuleList(rules []string) []string {
	seen := make(map[string]struct{}, len(rules))
	out := make([]string, 0, len(rules))

	for _, rule := range rules {
		normalized := strings.TrimSpace(rule)
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

func defaultToolsForTargetKind(targetKind string) []string {
	switch strings.ToLower(strings.TrimSpace(targetKind)) {
	case "repo", "repository", "codebase", "filesystem":
		return []string{"semgrep", "trivy", "gitleaks", "checkov"}
	default:
		return []string{"zap"}
	}
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

func supportedAdapters(capabilities []models.WorkerCapability) []string {
	seen := make(map[string]struct{}, len(capabilities))
	out := make([]string, 0, len(capabilities))

	for _, capability := range capabilities {
		key := strings.ToLower(strings.TrimSpace(capability.AdapterID))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}

	return out
}

func executionModeForTool(tool string) models.ExecutionMode {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "semgrep", "trivy", "gitleaks", "checkov":
		return models.ExecutionModePassive
	case "metasploit":
		return models.ExecutionModeRestrictedExploit
	case "zap":
		return models.ExecutionModeActiveValidation
	default:
		return models.ExecutionModeActiveValidation
	}
}

func approvedModulesForTool(tool string, targetKind string) []string {
	if strings.ToLower(strings.TrimSpace(tool)) != "metasploit" {
		return make([]string, 0)
	}

	switch strings.ToLower(strings.TrimSpace(targetKind)) {
	case "domain", "api":
		return []string{"auxiliary/scanner/http/http_version"}
	default:
		return []string{"auxiliary/scanner/http/http_version"}
	}
}

func maxRuntimeForTool(tool string) int64 {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "semgrep":
		return 300
	case "trivy":
		return 300
	case "gitleaks":
		return 180
	case "checkov":
		return 240
	case "zap":
		return 600
	case "metasploit":
		return 300
	default:
		return 180
	}
}
