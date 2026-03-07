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
	policyengine "unifiedsecurityscanner/control-plane/internal/policy"
)

var (
	jobSequence                      uint64
	leaseSequence                    uint64
	taskSequence                     uint64
	policySequence                   uint64
	policyVersionSequence            uint64
	policyApprovalSequence           uint64
	remediationSequence              uint64
	controlSequence                  uint64
	waiverSequence                   uint64
	occurrenceSequence               uint64
	activitySequence                 uint64
	verificationSequence             uint64
	exceptionSequence                uint64
	ticketSequence                   uint64
	remediationEvidenceSequence      uint64
	assignmentSequence               uint64
	notificationSequence             uint64
	scanTargetSequence               uint64
	webTargetSequence                uint64
	webAuthProfileSequence           uint64
	webCrawlPolicySequence           uint64
	webCoverageBaselineSequence      uint64
	webRuntimeCoverageRunSequence    uint64
	validationEngagementSequence     uint64
	validationAttackTraceSequence    uint64
	validationManualTestSequence     uint64
	validationEnvelopeSequence       uint64
	validationPlanStepSequence       uint64
	designReviewSequence             uint64
	designThreatSequence             uint64
	designDataFlowSequence           uint64
	designControlMappingSequence     uint64
	telemetryConnectorSequence       uint64
	telemetryEventSequence           uint64
	complianceMappingSequence        uint64
	detectionRulepackSequence        uint64
	detectionRulepackVersionSequence uint64
	detectionRulepackRolloutSequence uint64
	aiTriageRequestSequence          uint64
	apiAssetSequence                 uint64
	apiEndpointSequence              uint64
	externalAssetSequence            uint64
	ingestionSourceSequence          uint64
	ingestionEventSequence           uint64
	platformEventSequence            uint64
	ErrWorkerLeaseNotFound           = errors.New("worker lease not found")
	ErrTaskNotFound                  = errors.New("task not found")
	ErrProtectedToken                = errors.New("protected token")
	ErrWebTargetNotFound             = errors.New("web target not found")
	ErrWebAuthProfileNotFound        = errors.New("web auth profile not found")
	ErrWebAuthProfileDisabled        = errors.New("web auth profile disabled")
	ErrWebRuntimeToolNotAllowed      = errors.New("web runtime tool not allowed")
	ErrIngestionSourceNotFound       = errors.New("ingestion source not found")
	ErrInvalidIngestionToken         = errors.New("invalid ingestion token")
	ErrInvalidIngestionSignature     = errors.New("invalid ingestion signature")
	ErrIngestionSourceDisabled       = errors.New("ingestion source disabled")
	ErrInvalidIngestionSourceConfig  = errors.New("invalid ingestion source configuration")
	ErrInvalidWaiver                 = errors.New("invalid finding waiver")
	ErrInvalidRemediationTransition  = errors.New("invalid remediation transition")
	ErrInvalidVerification           = errors.New("invalid remediation verification")
	ErrInvalidExceptionDecision      = errors.New("invalid remediation exception")
	ErrInvalidAssignmentDecision     = errors.New("invalid remediation assignment")
	ErrKMSKeyNotFound                = errors.New("kms key not found")
	ErrSecretReferenceNotFound       = errors.New("secret reference not found")
	ErrSecretLeaseNotFound           = errors.New("secret lease not found")
	ErrSecretLeaseExpired            = errors.New("secret lease expired")
	ErrValidationEngagementRequired  = errors.New("validation engagement required")
	ErrValidationEngagementNotFound  = errors.New("validation engagement not found")
	ErrValidationEngagementInactive  = errors.New("validation engagement is not active")
	ErrValidationEngagementScope     = errors.New("validation engagement scope mismatch")
	ErrValidationEngagementTool      = errors.New("validation engagement does not allow requested tool")
	ErrValidationManualTestNotFound  = errors.New("validation manual test case not found")
	ErrValidationEnvelopeInactive    = errors.New("validation execution envelope is not active")
	ErrValidationPlanStepRequired    = errors.New("validation plan step approval is required")
	ErrValidationPlanStepNotFound    = errors.New("validation plan step not found")
	ErrValidationPlanStepNotApproved = errors.New("validation plan step is not approved")
	ErrValidationPlanStepDependency  = errors.New("validation plan step dependencies are not approved")
	ErrValidationPlanStepScope       = errors.New("validation plan step scope mismatch")
	ErrDesignReviewNotFound          = errors.New("design review not found")
	ErrDesignThreatNotFound          = errors.New("design threat not found")
	ErrDesignDataFlowNotFound        = errors.New("design data flow model not found")
	ErrDesignControlMappingNotFound  = errors.New("design control mapping not found")
	ErrTelemetryConnectorNotFound    = errors.New("runtime telemetry connector not found")
	ErrComplianceMappingNotFound     = errors.New("compliance control mapping not found")
	ErrDetectionRulepackNotFound     = errors.New("detection rulepack not found")
	ErrDetectionVersionNotFound      = errors.New("detection rulepack version not found")
	ErrAIPolicyModelDenied           = errors.New("ai model not permitted by policy")
	ErrAIPolicyInputTooLarge         = errors.New("ai input exceeds policy limits")
	ErrAIPolicyEvidenceRequired      = errors.New("ai evidence references are required by policy")
	ErrCertificateAuthorityDisabled  = errors.New("certificate authority is not configured")
	ErrWorkloadCertificateNotFound   = errors.New("workload certificate not found")
)

type TenantLimitExceededError struct {
	TenantID string
	Metric   string
	Limit    int64
	Current  int64
}

func (e *TenantLimitExceededError) Error() string {
	if e == nil {
		return "tenant limit exceeded"
	}
	return fmt.Sprintf("tenant limit exceeded for %s: current=%d limit=%d", e.Metric, e.Current, e.Limit)
}

type PolicyDeniedError struct {
	PolicyID string
	Reason   string
	RuleHits []string
}

func (e *PolicyDeniedError) Error() string {
	if e == nil {
		return "policy denied the requested operation"
	}
	if strings.TrimSpace(e.Reason) != "" {
		return e.Reason
	}
	return "policy denied the requested operation"
}

type EngineControlDeniedError struct {
	AdapterID  string
	TargetKind string
	Reason     string
}

func (e *EngineControlDeniedError) Error() string {
	if e == nil {
		return "scan engine control denied the requested operation"
	}
	if strings.TrimSpace(e.Reason) != "" {
		return strings.TrimSpace(e.Reason)
	}
	adapterID := strings.TrimSpace(e.AdapterID)
	targetKind := strings.TrimSpace(e.TargetKind)
	if adapterID == "" {
		return "scan engine control denied the requested operation"
	}
	if targetKind == "" {
		return fmt.Sprintf("scan adapter %s is disabled by tenant engine control", adapterID)
	}
	return fmt.Sprintf("scan adapter %s is disabled for target_kind %s by tenant engine control", adapterID, targetKind)
}

type Store struct {
	pool                        *pgxpool.Pool
	workerHeartbeatTTL          time.Duration
	bootstrapOrgID              string
	bootstrapOrgName            string
	oidcDefaultRole             string
	kmsMasterKey                string
	secretLeaseMaxTTL           time.Duration
	certificateAuthorityCertPEM string
	certificateAuthorityKeyPEM  string
	workloadCertificateTTL      time.Duration
	evidenceSigningKey          string
	evidenceSigningKeyID        string
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
		pool:                        pool,
		workerHeartbeatTTL:          cfg.WorkerHeartbeatTTL,
		bootstrapOrgID:              "bootstrap-org-" + normalizeSlug(cfg.BootstrapOrgSlug, "local"),
		bootstrapOrgName:            strings.TrimSpace(cfg.BootstrapOrgName),
		oidcDefaultRole:             normalizeRole(cfg.OIDCDefaultRole),
		kmsMasterKey:                strings.TrimSpace(cfg.KMSMasterKey),
		secretLeaseMaxTTL:           cfg.SecretLeaseMaxTTL,
		certificateAuthorityCertPEM: strings.TrimSpace(cfg.CertificateAuthorityCertPEM),
		certificateAuthorityKeyPEM:  strings.TrimSpace(cfg.CertificateAuthorityKeyPEM),
		workloadCertificateTTL:      cfg.WorkloadCertificateTTL,
		evidenceSigningKey:          strings.TrimSpace(cfg.EvidenceSigningKey),
		evidenceSigningKeyID:        strings.TrimSpace(cfg.EvidenceSigningKeyID),
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

	applicablePolicies, err := s.ListPoliciesForTenant(ctx, strings.TrimSpace(request.TenantID), 500)
	if err != nil {
		return models.ScanJob{}, fmt.Errorf("load policies for scan job: %w", err)
	}
	plan, rejection := policyengine.EvaluateSubmission(applicablePolicies, request, tools)
	if rejection != nil {
		return models.ScanJob{}, &PolicyDeniedError{
			PolicyID: rejection.PolicyID,
			Reason:   rejection.Reason,
			RuleHits: rejection.RuleHits,
		}
	}

	job := models.ScanJob{
		ID:           nextJobID(),
		TenantID:     strings.TrimSpace(request.TenantID),
		TargetKind:   strings.TrimSpace(request.TargetKind),
		Target:       strings.TrimSpace(request.Target),
		Profile:      strings.TrimSpace(request.Profile),
		RequestedBy:  strings.TrimSpace(request.RequestedBy),
		Tools:        tools,
		ApprovalMode: combineApprovalMode(approvalModeForTools(tools), plan.ApprovalMode),
		Status:       models.ScanJobStatusQueued,
		RequestedAt:  now,
		UpdatedAt:    now,
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.ScanJob{}, fmt.Errorf("begin create job tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.enforceScanJobTenantLimitsTx(ctx, tx, job.TenantID); err != nil {
		return models.ScanJob{}, err
	}
	violation, err := checkTenantExecutionControlsTx(ctx, tx, job.TenantID, job.TargetKind, now)
	if err != nil {
		return models.ScanJob{}, err
	}
	if violation != nil {
		return models.ScanJob{}, violation
	}

	engineControls, err := loadEffectiveScanEngineControlsTx(ctx, tx, job.TenantID, job.TargetKind, tools)
	if err != nil {
		return models.ScanJob{}, err
	}
	for _, tool := range tools {
		control, exists := engineControls[tool]
		if exists && !control.Enabled {
			return models.ScanJob{}, &EngineControlDeniedError{
				AdapterID:  tool,
				TargetKind: job.TargetKind,
			}
		}
	}

	validationContext, err := resolveValidationEngagementContextTx(
		ctx,
		tx,
		job.TenantID,
		job.TargetKind,
		job.Target,
		tools,
		request.TaskLabels,
		now,
	)
	if err != nil {
		return models.ScanJob{}, err
	}

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
		labels := map[string]string{
			"scan_job_id": job.ID,
			"profile":     job.Profile,
		}
		for key, value := range request.TaskLabels {
			normalizedKey := strings.ToLower(strings.TrimSpace(key))
			normalizedValue := strings.TrimSpace(value)
			if normalizedKey == "" || normalizedValue == "" {
				continue
			}
			if normalizedKey == "scan_job_id" || normalizedKey == "profile" {
				continue
			}
			labels[normalizedKey] = normalizedValue
		}
		if validationContext != nil {
			for key, value := range validationContext.Labels {
				normalizedKey := strings.ToLower(strings.TrimSpace(key))
				normalizedValue := strings.TrimSpace(value)
				if normalizedKey == "" || normalizedValue == "" {
					continue
				}
				if normalizedKey == "scan_job_id" || normalizedKey == "profile" {
					continue
				}
				labels[normalizedKey] = normalizedValue
			}
		}
		maxRuntimeSeconds := maxRuntimeForTool(tool)
		if control, exists := engineControls[tool]; exists {
			if strings.TrimSpace(control.RulepackVersion) != "" {
				labels["rulepack_version"] = strings.TrimSpace(control.RulepackVersion)
				if strings.TrimSpace(control.TargetKind) == "" {
					labels["rulepack_scope"] = "global"
				} else {
					labels["rulepack_scope"] = strings.TrimSpace(control.TargetKind)
				}
			}
			if control.MaxRuntimeSeconds > 0 {
				maxRuntimeSeconds = control.MaxRuntimeSeconds
			}
		}
		labelsJSON, err := json.Marshal(labels)
		if err != nil {
			return models.ScanJob{}, fmt.Errorf("marshal task labels: %w", err)
		}

		decision := plan.Decisions[tool]
		policyStatus := string(policyengine.TaskDecisionApproved)
		policyReason := ""
		ruleHitsJSON := []byte("[]")
		if decision.Status != "" {
			policyStatus = string(decision.Status)
			policyReason = strings.TrimSpace(decision.Reason)
			payload, err := json.Marshal(decision.RuleHits)
			if err != nil {
				return models.ScanJob{}, fmt.Errorf("marshal policy rule hits: %w", err)
			}
			ruleHitsJSON = payload
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO scan_job_tasks (
				id, scan_job_id, tenant_id, adapter_id, target_kind, target,
				status, approved_modules, labels_json, max_runtime_seconds,
				evidence_upload_url, policy_status, policy_reason, policy_rule_hits_json,
				created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10,
				$11, $12, $13, $14,
				$15, $15
			)
		`, taskID, job.ID, job.TenantID, tool, job.TargetKind, job.Target,
			string(models.TaskStatusQueued), approvedModulesForTool(tool, job.TargetKind), labelsJSON, maxRuntimeSeconds,
			fmt.Sprintf("local://evidence/%s", taskID), policyStatus, policyReason, ruleHitsJSON, now)
		if err != nil {
			return models.ScanJob{}, fmt.Errorf("insert scan job task: %w", err)
		}

		if decision.Status == policyengine.TaskDecisionPendingApproval {
			_, err = tx.Exec(ctx, `
				INSERT INTO policy_approvals (
					id, tenant_id, scan_job_id, task_id, policy_id, action, status, requested_by, created_at
				) VALUES (
					$1, $2, $3, $4, $5, $6, 'pending', $7, $8
				)
			`, nextPolicyApprovalID(), job.TenantID, job.ID, taskID, decision.PolicyID, "scan_task.dispatch", job.RequestedBy, now)
			if err != nil {
				return models.ScanJob{}, fmt.Errorf("insert policy approval: %w", err)
			}
		}
	}

	if err := publishPlatformEventTx(ctx, tx, models.PlatformEvent{
		TenantID:      job.TenantID,
		EventType:     "scan_job.created",
		SourceService: "control-plane",
		AggregateType: "scan_job",
		AggregateID:   job.ID,
		Payload: map[string]any{
			"target_kind":   job.TargetKind,
			"target":        job.Target,
			"profile":       job.Profile,
			"tool_count":    len(job.Tools),
			"approval_mode": job.ApprovalMode,
		},
		CreatedAt: now,
	}); err != nil {
		return models.ScanJob{}, err
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

	if err := s.publishPlatformEvent(ctx, models.PlatformEvent{
		EventType:     "worker.registered",
		SourceService: "control-plane",
		AggregateType: "worker",
		AggregateID:   strings.TrimSpace(request.WorkerID),
		Payload: map[string]any{
			"lease_id":           leaseID,
			"operating_system":   request.OperatingSystem,
			"worker_version":     request.WorkerVersion,
			"capability_count":   len(request.Capabilities),
			"heartbeat_interval": heartbeatIntervalSeconds,
		},
		CreatedAt: now,
	}); err != nil {
		return models.WorkerRegistrationResponse{}, err
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

	assignments, err := claimAssignmentsTx(ctx, tx, request.WorkerID, request.LeaseID, capabilitiesJSON, now, 3, s.secretLeaseMaxTTL)
	if err != nil {
		return models.HeartbeatResponse{}, err
	}

	if len(assignments) > 0 {
		if err := publishPlatformEventTx(ctx, tx, models.PlatformEvent{
			EventType:     "worker.assignments.claimed",
			SourceService: "control-plane",
			AggregateType: "worker",
			AggregateID:   strings.TrimSpace(request.WorkerID),
			Payload: map[string]any{
				"lease_id":         strings.TrimSpace(request.LeaseID),
				"assignment_count": len(assignments),
			},
			CreatedAt: now,
		}); err != nil {
			return models.HeartbeatResponse{}, err
		}
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
	var taskLabelsJSON []byte
	err = tx.QueryRow(ctx, `
		SELECT id, scan_job_id, tenant_id, adapter_id, target_kind, target, labels_json
		FROM scan_job_tasks
		WHERE id = $1
	`, strings.TrimSpace(submission.TaskID)).Scan(
		&task.TaskID,
		&task.ScanJobID,
		&task.TenantID,
		&task.AdapterID,
		&task.TargetKind,
		&task.Target,
		&taskLabelsJSON,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTaskNotFound
		}
		return fmt.Errorf("load task for finalize: %w", err)
	}

	taskLabels := map[string]string{}
	if len(taskLabelsJSON) > 0 {
		if err := json.Unmarshal(taskLabelsJSON, &taskLabels); err != nil {
			return fmt.Errorf("unmarshal task labels for finalize: %w", err)
		}
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

	envelope, err := loadAssetRiskEnvelopeTx(ctx, tx, task.TenantID, task.Target)
	if err != nil {
		return err
	}

	for _, finding := range submission.ReportedFindings {
		if err := persistFindingTx(ctx, tx, task, finding, now, envelope); err != nil {
			return err
		}
	}

	registeredEvidenceCount, err := s.registerTaskEvidenceTx(ctx, tx, task, submission.WorkerID, submission.EvidencePaths, now)
	if err != nil {
		return err
	}
	coverageRunIngested, err := ingestWebRuntimeCoverageRunTx(ctx, tx, task, taskLabels, submission, now)
	if err != nil {
		return err
	}

	if err := recomputeScanJobStatusTx(ctx, tx, task.ScanJobID, now); err != nil {
		return err
	}

	if err := publishPlatformEventTx(ctx, tx, models.PlatformEvent{
		TenantID:      task.TenantID,
		EventType:     "scan_task.finalized",
		SourceService: "control-plane",
		AggregateType: "scan_job",
		AggregateID:   task.ScanJobID,
		Payload: map[string]any{
			"task_id":                   task.TaskID,
			"worker_id":                 strings.TrimSpace(submission.WorkerID),
			"final_state":               string(finalStatus),
			"reported_finding_count":    len(submission.ReportedFindings),
			"reported_evidence_count":   len(submission.EvidencePaths),
			"registered_evidence_count": registeredEvidenceCount,
			"coverage_run_ingested":     coverageRunIngested,
		},
		CreatedAt: now,
	}); err != nil {
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
		ORDER BY COALESCE(NULLIF(finding_json->'risk'->>'overall_score', '')::double precision, 0) DESC,
		         updated_at DESC
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
		SELECT tenant_id, id, version_number, name, scope, mode, enabled, rules_json, updated_by, created_at, updated_at
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
			&policy.TenantID,
			&policy.ID,
			&policy.VersionNumber,
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
		ID:            nextPolicyID(),
		VersionNumber: 1,
		Name:          strings.TrimSpace(request.Name),
		Scope:         strings.TrimSpace(request.Scope),
		Mode:          strings.TrimSpace(request.Mode),
		Enabled:       request.Enabled,
		Rules:         sanitizeRuleList(request.Rules),
		UpdatedBy:     strings.TrimSpace(request.UpdatedBy),
		CreatedAt:     now,
		UpdatedAt:     now,
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

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.Policy{}, fmt.Errorf("begin create policy tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO policies (
			id, tenant_id, version_number, name, scope, mode, enabled, rules_json, updated_by, created_at, updated_at
		) VALUES (
			$1, '', $2, $3, $4, $5, $6, $7, $8, $9, $9
		)
	`, policy.ID, policy.VersionNumber, policy.Name, policy.Scope, policy.Mode, policy.Enabled, rulesJSON, policy.UpdatedBy, now)
	if err != nil {
		return models.Policy{}, fmt.Errorf("insert policy: %w", err)
	}

	if err := recordPolicyVersionTx(ctx, tx, policy, "created", policy.UpdatedBy); err != nil {
		return models.Policy{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.Policy{}, fmt.Errorf("commit create policy tx: %w", err)
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
	secretLeaseMaxTTL time.Duration,
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

	queryLimit := limit * 5
	if queryLimit < limit {
		queryLimit = limit
	}

	rows, err := tx.Query(ctx, `
		SELECT id, scan_job_id, tenant_id, adapter_id, target_kind, target,
		       approved_modules, labels_json, max_runtime_seconds, evidence_upload_url
		FROM scan_job_tasks
		WHERE status = 'queued'
		  AND policy_status = 'approved'
		  AND adapter_id = ANY($1)
		ORDER BY created_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, adapters, queryLimit)
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
	tenantDecisionCache := make(map[string]*ExecutionControlViolationError)
	for _, task := range queued {
		cacheKey := task.tenantID + "|" + task.targetKind
		violation, seen := tenantDecisionCache[cacheKey]
		if !seen {
			decision, err := checkTenantExecutionControlsTx(ctx, tx, task.tenantID, task.targetKind, now)
			if err != nil {
				return nil, err
			}
			tenantDecisionCache[cacheKey] = decision
			violation = decision
		}
		if violation != nil {
			continue
		}
		if len(assignments) >= limit {
			break
		}
		if err := ensureValidationEngagementForDispatchTx(
			ctx,
			tx,
			task.tenantID,
			task.targetKind,
			task.target,
			task.adapterID,
			task.labels,
			now,
		); err != nil {
			continue
		}
		if err := attachWebAuthSecretLeasesTx(ctx, tx, task.tenantID, task.taskID, workerID, task.labels, task.maxRuntimeSeconds, secretLeaseMaxTTL, now); err != nil {
			return nil, err
		}

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

func attachWebAuthSecretLeasesTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	taskID string,
	workerID string,
	labels map[string]string,
	maxRuntimeSeconds int64,
	secretLeaseMaxTTL time.Duration,
	now time.Time,
) error {
	if len(labels) == 0 {
		return nil
	}

	type secretLeaseLabelDescriptor struct {
		secretPathLabelKey     string
		referenceIDLabelKey    string
		leaseIDLabelKey        string
		leaseTokenLabelKey     string
		leaseExpiresAtLabelKey string
	}

	descriptors := []secretLeaseLabelDescriptor{
		{
			secretPathLabelKey:     "web_auth_username_secret_ref",
			referenceIDLabelKey:    "web_auth_username_secret_reference_id",
			leaseIDLabelKey:        "web_auth_username_secret_lease_id",
			leaseTokenLabelKey:     "web_auth_username_secret_lease_token",
			leaseExpiresAtLabelKey: "web_auth_username_secret_lease_expires_at",
		},
		{
			secretPathLabelKey:     "web_auth_password_secret_ref",
			referenceIDLabelKey:    "web_auth_password_secret_reference_id",
			leaseIDLabelKey:        "web_auth_password_secret_lease_id",
			leaseTokenLabelKey:     "web_auth_password_secret_lease_token",
			leaseExpiresAtLabelKey: "web_auth_password_secret_lease_expires_at",
		},
		{
			secretPathLabelKey:     "web_auth_bearer_token_secret_ref",
			referenceIDLabelKey:    "web_auth_bearer_token_secret_reference_id",
			leaseIDLabelKey:        "web_auth_bearer_token_secret_lease_id",
			leaseTokenLabelKey:     "web_auth_bearer_token_secret_lease_token",
			leaseExpiresAtLabelKey: "web_auth_bearer_token_secret_lease_expires_at",
		},
	}

	leaseTTL := secretLeaseTTLForTask(maxRuntimeSeconds, secretLeaseMaxTTL)
	for _, descriptor := range descriptors {
		secretPath := strings.TrimSpace(labels[descriptor.secretPathLabelKey])
		if secretPath == "" {
			continue
		}

		referenceID, err := resolveSecretReferenceIDByPathTx(ctx, tx, tenantID, secretPath)
		if err != nil {
			if errors.Is(err, ErrSecretReferenceNotFound) {
				return fmt.Errorf("resolve %s for task %s: %w", descriptor.secretPathLabelKey, taskID, err)
			}
			return err
		}

		issued, err := issueSecretLeaseTx(ctx, tx, tenantID, "control-plane:worker-assignment", workerID, referenceID, leaseTTL, now)
		if err != nil {
			return fmt.Errorf("issue secret lease for task %s: %w", taskID, err)
		}

		labels[descriptor.referenceIDLabelKey] = issued.Lease.SecretReferenceID
		labels[descriptor.leaseIDLabelKey] = issued.Lease.ID
		labels[descriptor.leaseTokenLabelKey] = issued.LeaseToken
		labels[descriptor.leaseExpiresAtLabelKey] = issued.Lease.ExpiresAt.Format(time.RFC3339)

		if err := publishPlatformEventTx(ctx, tx, models.PlatformEvent{
			TenantID:      tenantID,
			EventType:     "secret_lease.issued",
			SourceService: "control-plane",
			AggregateType: "secret_lease",
			AggregateID:   issued.Lease.ID,
			Payload: map[string]any{
				"secret_reference_id": issued.Lease.SecretReferenceID,
				"worker_id":           issued.Lease.WorkerID,
				"task_id":             taskID,
				"secret_path_label":   descriptor.secretPathLabelKey,
				"expires_at":          issued.Lease.ExpiresAt,
			},
			CreatedAt: now,
		}); err != nil {
			return err
		}
	}

	return nil
}

func resolveSecretReferenceIDByPathTx(ctx context.Context, tx pgx.Tx, tenantID string, secretPath string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	secretPath = strings.TrimSpace(secretPath)
	if tenantID == "" || secretPath == "" {
		return "", ErrSecretReferenceNotFound
	}

	var referenceID string
	err := tx.QueryRow(ctx, `
		SELECT id
		FROM secret_references
		WHERE tenant_id = $1
		  AND secret_path = $2
		ORDER BY updated_at DESC, id DESC
		LIMIT 1
	`, tenantID, secretPath).Scan(&referenceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrSecretReferenceNotFound
		}
		return "", fmt.Errorf("query secret reference by path: %w", err)
	}

	return strings.TrimSpace(referenceID), nil
}

func secretLeaseTTLForTask(maxRuntimeSeconds int64, maxTTL time.Duration) time.Duration {
	ttl := 10 * time.Minute
	if maxRuntimeSeconds > 0 {
		runtimeTTL := (time.Duration(maxRuntimeSeconds) * time.Second) + (2 * time.Minute)
		if runtimeTTL > ttl {
			ttl = runtimeTTL
		}
	}
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl
}

func recomputeScanJobStatusTx(ctx context.Context, tx pgx.Tx, scanJobID string, now time.Time) error {
	var total, queued, running, completed, failed, canceled int
	err := tx.QueryRow(ctx, `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE status = 'queued') AS queued,
			COUNT(*) FILTER (WHERE status = 'running') AS running,
			COUNT(*) FILTER (WHERE status = 'completed') AS completed,
			COUNT(*) FILTER (WHERE status = 'failed') AS failed,
			COUNT(*) FILTER (WHERE status = 'canceled') AS canceled
		FROM scan_job_tasks
		WHERE scan_job_id = $1
	`, scanJobID).Scan(&total, &queued, &running, &completed, &failed, &canceled)
	if err != nil {
		return fmt.Errorf("query task aggregate: %w", err)
	}

	nextStatus := string(models.ScanJobStatusQueued)
	switch {
	case total == 0:
		nextStatus = string(models.ScanJobStatusQueued)
	case completed == total:
		nextStatus = string(models.ScanJobStatusCompleted)
	case failed+canceled == total:
		nextStatus = string(models.ScanJobStatusFailed)
	case running > 0:
		nextStatus = string(models.ScanJobStatusRunning)
	case queued > 0:
		nextStatus = string(models.ScanJobStatusQueued)
	default:
		nextStatus = string(models.ScanJobStatusRunning)
	}

	_, err = tx.Exec(ctx, `
		UPDATE scan_jobs
		SET status = $1,
		    running_task_count = $2,
		    updated_at = $3
		WHERE id = $4
	`, nextStatus, running, now, scanJobID)
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

func nextPolicyVersionID() string {
	sequence := atomic.AddUint64(&policyVersionSequence, 1)
	return fmt.Sprintf("policy-version-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextPolicyApprovalID() string {
	sequence := atomic.AddUint64(&policyApprovalSequence, 1)
	return fmt.Sprintf("policy-approval-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextRemediationID() string {
	sequence := atomic.AddUint64(&remediationSequence, 1)
	return fmt.Sprintf("remediation-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextControlID() string {
	sequence := atomic.AddUint64(&controlSequence, 1)
	return fmt.Sprintf("control-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextWaiverID() string {
	sequence := atomic.AddUint64(&waiverSequence, 1)
	return fmt.Sprintf("waiver-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextOccurrenceID() string {
	sequence := atomic.AddUint64(&occurrenceSequence, 1)
	return fmt.Sprintf("finding-occurrence-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextActivityID() string {
	sequence := atomic.AddUint64(&activitySequence, 1)
	return fmt.Sprintf("remediation-activity-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextVerificationID() string {
	sequence := atomic.AddUint64(&verificationSequence, 1)
	return fmt.Sprintf("remediation-verification-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextExceptionID() string {
	sequence := atomic.AddUint64(&exceptionSequence, 1)
	return fmt.Sprintf("remediation-exception-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextTicketID() string {
	sequence := atomic.AddUint64(&ticketSequence, 1)
	return fmt.Sprintf("remediation-ticket-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextRemediationEvidenceID() string {
	sequence := atomic.AddUint64(&remediationEvidenceSequence, 1)
	return fmt.Sprintf("remediation-evidence-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextAssignmentRequestID() string {
	sequence := atomic.AddUint64(&assignmentSequence, 1)
	return fmt.Sprintf("remediation-assignment-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextNotificationID() string {
	sequence := atomic.AddUint64(&notificationSequence, 1)
	return fmt.Sprintf("notification-%d-%06d", time.Now().UTC().Unix(), sequence)
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

func sanitizeRuleList(rules models.PolicyRuleSet) models.PolicyRuleSet {
	return models.NormalizePolicyRuleSet([]models.PolicyRule(rules))
}

func defaultToolsForTargetKind(targetKind string) []string {
	switch strings.ToLower(strings.TrimSpace(targetKind)) {
	case "go_repo":
		return []string{"semgrep", "gosec", "trivy", "osv-scanner", "syft", "grype", "trivy-config", "trivy-secrets", "gitleaks", "detect-secrets", "checkov"}
	case "java_repo":
		return []string{"semgrep", "spotbugs", "pmd", "trivy", "osv-scanner", "syft", "grype", "trivy-config", "trivy-secrets", "gitleaks", "detect-secrets", "checkov"}
	case "node_repo":
		return []string{"semgrep", "eslint", "trivy", "npm-audit", "osv-scanner", "syft", "grype", "trivy-config", "trivy-secrets", "gitleaks", "detect-secrets", "checkov"}
	case "dotnet_repo":
		return []string{"semgrep", "devskim", "trivy", "dotnet-audit", "osv-scanner", "syft", "grype", "trivy-config", "trivy-secrets", "gitleaks", "detect-secrets", "checkov"}
	case "ruby_repo":
		return []string{"semgrep", "brakeman", "trivy", "bundler-audit", "osv-scanner", "syft", "grype", "trivy-config", "trivy-secrets", "gitleaks", "detect-secrets", "checkov"}
	case "php_repo":
		return []string{"semgrep", "phpstan", "trivy", "composer-audit", "syft", "grype", "trivy-config", "trivy-secrets", "gitleaks", "detect-secrets", "checkov"}
	case "mobile_repo", "android_repo", "ios_repo":
		return []string{"mobsfscan", "semgrep", "trivy", "osv-scanner", "syft", "grype", "trivy-config", "trivy-secrets", "gitleaks", "detect-secrets", "checkov"}
	case "aws_account":
		return []string{"prowler"}
	case "gcp_project":
		return []string{"prowler"}
	case "azure_subscription":
		return []string{"prowler"}
	case "api_schema":
		return []string{"zap-api"}
	case "shell_script":
		return []string{"shellcheck"}
	case "dockerfile":
		return []string{"hadolint", "kics", "trivy-config"}
	case "terraform":
		return []string{"tfsec", "kics", "trivy-config", "checkov"}
	case "kubernetes":
		return []string{"kube-score", "kubesec", "kics", "trivy-config", "checkov"}
	case "cloudformation":
		return []string{"cfn-lint", "kics", "trivy-config", "checkov"}
	case "domain":
		return []string{"zap", "nuclei"}
	case "host", "ip":
		return []string{"nmap", "nuclei"}
	case "api", "url":
		return []string{"zap", "nuclei", "browser-probe"}
	case "repo", "repository", "codebase", "filesystem":
		return []string{"semgrep", "bandit", "trivy", "osv-scanner", "syft", "grype", "trivy-config", "trivy-secrets", "gitleaks", "detect-secrets", "checkov"}
	case "image", "container_image":
		return []string{"syft", "trivy-image", "grype", "trivy-config"}
	default:
		return []string{"zap"}
	}
}

func approvalModeForTools(tools []string) string {
	for _, tool := range tools {
		switch tool {
		case "metasploit", "sqlmap", "nmap", "nuclei", "zap", "browser-probe":
			return "policy-gated"
		}
	}

	return "standard"
}

func combineApprovalMode(base string, policyMode string) string {
	if strings.TrimSpace(policyMode) == "manual-approval" {
		return "manual-approval"
	}
	return base
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
	case "semgrep", "gosec", "spotbugs", "pmd", "bundler-audit", "brakeman", "devskim", "bandit", "eslint", "phpstan", "shellcheck", "mobsfscan", "detect-secrets", "dotnet-audit", "npm-audit", "composer-audit", "osv-scanner", "syft", "trivy", "trivy-image", "trivy-config", "trivy-secrets", "grype", "gitleaks", "checkov", "cfn-lint", "hadolint", "kics", "prowler", "kubesec", "kube-score", "tfsec":
		return models.ExecutionModePassive
	case "zap-api", "nuclei", "browser-probe":
		return models.ExecutionModeActiveValidation
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
	case "gosec":
		return 240
	case "spotbugs":
		return 360
	case "pmd":
		return 300
	case "bundler-audit":
		return 180
	case "brakeman":
		return 360
	case "devskim":
		return 300
	case "bandit":
		return 240
	case "eslint":
		return 240
	case "phpstan":
		return 240
	case "shellcheck":
		return 120
	case "mobsfscan":
		return 300
	case "detect-secrets":
		return 180
	case "npm-audit":
		return 180
	case "composer-audit":
		return 180
	case "dotnet-audit":
		return 240
	case "osv-scanner":
		return 240
	case "syft":
		return 180
	case "trivy":
		return 300
	case "trivy-image":
		return 420
	case "trivy-config":
		return 300
	case "trivy-secrets":
		return 240
	case "grype":
		return 360
	case "gitleaks":
		return 180
	case "checkov":
		return 240
	case "cfn-lint":
		return 180
	case "hadolint":
		return 120
	case "kics":
		return 300
	case "prowler":
		return 900
	case "nuclei":
		return 300
	case "kubesec":
		return 180
	case "kube-score":
		return 180
	case "tfsec":
		return 240
	case "zap-api":
		return 600
	case "zap":
		return 600
	case "browser-probe":
		return 600
	case "metasploit":
		return 300
	default:
		return 180
	}
}
