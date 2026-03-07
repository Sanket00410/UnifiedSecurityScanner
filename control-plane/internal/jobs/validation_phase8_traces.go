package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListValidationAttackTracesForTenant(ctx context.Context, tenantID string, engagementID string, limit int) ([]models.ValidationAttackTrace, error) {
	tenantID = strings.TrimSpace(tenantID)
	engagementID = strings.TrimSpace(engagementID)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, engagement_id, scan_job_id, task_id, adapter_id,
		       target_kind, target, title, summary, severity,
		       evidence_refs_json, artifacts_json, replay_manifest_json,
		       created_by, created_at, updated_at
		FROM validation_attack_traces
		WHERE tenant_id = $1
		  AND ($2 = '' OR engagement_id = $2)
		ORDER BY updated_at DESC, id DESC
		LIMIT $3
	`, tenantID, engagementID, limit)
	if err != nil {
		return nil, fmt.Errorf("list validation attack traces: %w", err)
	}
	defer rows.Close()

	items := make([]models.ValidationAttackTrace, 0, limit)
	for rows.Next() {
		item, err := scanValidationAttackTrace(rows)
		if err != nil {
			return nil, fmt.Errorf("scan validation attack trace row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate validation attack traces: %w", err)
	}

	return items, nil
}

func (s *Store) CreateValidationAttackTraceForTenant(ctx context.Context, tenantID string, actor string, request models.CreateValidationAttackTraceRequest) (models.ValidationAttackTrace, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	engagementID := strings.TrimSpace(request.EngagementID)
	if engagementID == "" {
		return models.ValidationAttackTrace{}, ErrValidationEngagementRequired
	}
	title := strings.TrimSpace(request.Title)
	if title == "" {
		return models.ValidationAttackTrace{}, fmt.Errorf("title is required")
	}

	now := time.Now().UTC()
	item := models.ValidationAttackTrace{
		ID:             nextValidationAttackTraceID(),
		TenantID:       tenantID,
		EngagementID:   engagementID,
		ScanJobID:      strings.TrimSpace(request.ScanJobID),
		TaskID:         strings.TrimSpace(request.TaskID),
		AdapterID:      strings.ToLower(strings.TrimSpace(request.AdapterID)),
		TargetKind:     strings.ToLower(strings.TrimSpace(request.TargetKind)),
		Target:         strings.TrimSpace(request.Target),
		Title:          title,
		Summary:        strings.TrimSpace(request.Summary),
		Severity:       normalizeValidationTraceSeverity(request.Severity),
		EvidenceRefs:   sanitizeValidationStringList(request.EvidenceRefs),
		Artifacts:      cloneValidationMap(request.Artifacts),
		ReplayManifest: cloneValidationMap(request.ReplayManifest),
		CreatedBy:      actor,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	evidenceJSON, err := json.Marshal(item.EvidenceRefs)
	if err != nil {
		return models.ValidationAttackTrace{}, fmt.Errorf("marshal validation attack trace evidence refs: %w", err)
	}
	artifactsJSON, err := json.Marshal(item.Artifacts)
	if err != nil {
		return models.ValidationAttackTrace{}, fmt.Errorf("marshal validation attack trace artifacts: %w", err)
	}
	replayJSON, err := json.Marshal(item.ReplayManifest)
	if err != nil {
		return models.ValidationAttackTrace{}, fmt.Errorf("marshal validation attack trace replay manifest: %w", err)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.ValidationAttackTrace{}, fmt.Errorf("begin validation attack trace tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, found, err := getValidationEngagementTx(ctx, tx, tenantID, engagementID)
	if err != nil {
		return models.ValidationAttackTrace{}, err
	}
	if !found {
		return models.ValidationAttackTrace{}, ErrValidationEngagementNotFound
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO validation_attack_traces (
			id, tenant_id, engagement_id, scan_job_id, task_id, adapter_id,
			target_kind, target, title, summary, severity,
			evidence_refs_json, artifacts_json, replay_manifest_json,
			created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14,
			$15, $16, $16
		)
		RETURNING id, tenant_id, engagement_id, scan_job_id, task_id, adapter_id,
		          target_kind, target, title, summary, severity,
		          evidence_refs_json, artifacts_json, replay_manifest_json,
		          created_by, created_at, updated_at
	`,
		item.ID, item.TenantID, item.EngagementID, item.ScanJobID, item.TaskID, item.AdapterID,
		item.TargetKind, item.Target, item.Title, item.Summary, item.Severity,
		evidenceJSON, artifactsJSON, replayJSON,
		item.CreatedBy, item.CreatedAt,
	)

	created, err := scanValidationAttackTrace(row)
	if err != nil {
		return models.ValidationAttackTrace{}, fmt.Errorf("create validation attack trace: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.ValidationAttackTrace{}, fmt.Errorf("commit validation attack trace tx: %w", err)
	}

	return created, nil
}

func (s *Store) ListValidationManualTestsForTenant(ctx context.Context, tenantID string, engagementID string, status string, limit int) ([]models.ValidationManualTestCase, error) {
	tenantID = strings.TrimSpace(tenantID)
	engagementID = strings.TrimSpace(engagementID)
	status = normalizeValidationManualTestStatus(status)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, engagement_id, wstg_id, category, title, status,
		       assigned_to, notes, evidence_refs_json,
		       completed_by, completed_at, created_by, created_at, updated_at
		FROM validation_manual_test_cases
		WHERE tenant_id = $1
		  AND ($2 = '' OR engagement_id = $2)
		  AND ($3 = '' OR status = $3)
		ORDER BY updated_at DESC, id DESC
		LIMIT $4
	`, tenantID, engagementID, status, limit)
	if err != nil {
		return nil, fmt.Errorf("list validation manual tests: %w", err)
	}
	defer rows.Close()

	items := make([]models.ValidationManualTestCase, 0, limit)
	for rows.Next() {
		item, err := scanValidationManualTestCase(rows)
		if err != nil {
			return nil, fmt.Errorf("scan validation manual test row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate validation manual tests: %w", err)
	}

	return items, nil
}

func (s *Store) CreateValidationManualTestForTenant(ctx context.Context, tenantID string, actor string, request models.CreateValidationManualTestCaseRequest) (models.ValidationManualTestCase, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	engagementID := strings.TrimSpace(request.EngagementID)
	if engagementID == "" {
		return models.ValidationManualTestCase{}, ErrValidationEngagementRequired
	}
	title := strings.TrimSpace(request.Title)
	if title == "" {
		return models.ValidationManualTestCase{}, fmt.Errorf("title is required")
	}

	status := normalizeValidationManualTestStatus(request.Status)
	if status == "" {
		status = "not_started"
	}

	now := time.Now().UTC()
	item := models.ValidationManualTestCase{
		ID:           nextValidationManualTestID(),
		TenantID:     tenantID,
		EngagementID: engagementID,
		WSTGID:       strings.ToUpper(strings.TrimSpace(request.WSTGID)),
		Category:     strings.TrimSpace(request.Category),
		Title:        title,
		Status:       status,
		AssignedTo:   strings.TrimSpace(request.AssignedTo),
		Notes:        strings.TrimSpace(request.Notes),
		EvidenceRefs: sanitizeValidationStringList(request.EvidenceRefs),
		CreatedBy:    actor,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if isValidationManualTestCompleteStatus(item.Status) {
		item.CompletedBy = actor
		item.CompletedAt = &now
	}

	evidenceJSON, err := json.Marshal(item.EvidenceRefs)
	if err != nil {
		return models.ValidationManualTestCase{}, fmt.Errorf("marshal validation manual test evidence refs: %w", err)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.ValidationManualTestCase{}, fmt.Errorf("begin validation manual test tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, found, err := getValidationEngagementTx(ctx, tx, tenantID, engagementID)
	if err != nil {
		return models.ValidationManualTestCase{}, err
	}
	if !found {
		return models.ValidationManualTestCase{}, ErrValidationEngagementNotFound
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO validation_manual_test_cases (
			id, tenant_id, engagement_id, wstg_id, category, title, status,
			assigned_to, notes, evidence_refs_json,
			completed_by, completed_at, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10,
			$11, $12, $13, $14, $14
		)
		RETURNING id, tenant_id, engagement_id, wstg_id, category, title, status,
		          assigned_to, notes, evidence_refs_json,
		          completed_by, completed_at, created_by, created_at, updated_at
	`, item.ID, item.TenantID, item.EngagementID, item.WSTGID, item.Category, item.Title, item.Status,
		item.AssignedTo, item.Notes, evidenceJSON,
		item.CompletedBy, item.CompletedAt, item.CreatedBy, item.CreatedAt)

	created, err := scanValidationManualTestCase(row)
	if err != nil {
		return models.ValidationManualTestCase{}, fmt.Errorf("create validation manual test: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.ValidationManualTestCase{}, fmt.Errorf("commit validation manual test tx: %w", err)
	}

	return created, nil
}

func (s *Store) UpdateValidationManualTestForTenant(ctx context.Context, tenantID string, testCaseID string, actor string, request models.UpdateValidationManualTestCaseRequest) (models.ValidationManualTestCase, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	testCaseID = strings.TrimSpace(testCaseID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.ValidationManualTestCase{}, false, fmt.Errorf("begin validation manual test update tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		SELECT id, tenant_id, engagement_id, wstg_id, category, title, status,
		       assigned_to, notes, evidence_refs_json,
		       completed_by, completed_at, created_by, created_at, updated_at
		FROM validation_manual_test_cases
		WHERE tenant_id = $1
		  AND id = $2
		FOR UPDATE
	`, tenantID, testCaseID)

	current, err := scanValidationManualTestCase(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationManualTestCase{}, false, nil
		}
		return models.ValidationManualTestCase{}, false, fmt.Errorf("load validation manual test for update: %w", err)
	}

	if value := strings.TrimSpace(request.WSTGID); value != "" {
		current.WSTGID = strings.ToUpper(value)
	}
	if value := strings.TrimSpace(request.Category); value != "" {
		current.Category = value
	}
	if value := strings.TrimSpace(request.Title); value != "" {
		current.Title = value
	}
	if value := strings.TrimSpace(request.AssignedTo); value != "" {
		current.AssignedTo = value
	}
	if value := strings.TrimSpace(request.Notes); value != "" {
		current.Notes = value
	}
	if request.EvidenceRefs != nil {
		current.EvidenceRefs = sanitizeValidationStringList(request.EvidenceRefs)
	}
	if value := normalizeValidationManualTestStatus(request.Status); value != "" {
		current.Status = value
	}
	current.UpdatedAt = time.Now().UTC()
	if isValidationManualTestCompleteStatus(current.Status) {
		current.CompletedBy = actor
		completedAt := current.UpdatedAt
		current.CompletedAt = &completedAt
	} else {
		current.CompletedBy = ""
		current.CompletedAt = nil
	}

	evidenceJSON, err := json.Marshal(current.EvidenceRefs)
	if err != nil {
		return models.ValidationManualTestCase{}, false, fmt.Errorf("marshal validation manual test update evidence refs: %w", err)
	}

	row = tx.QueryRow(ctx, `
		UPDATE validation_manual_test_cases
		SET wstg_id = $3,
		    category = $4,
		    title = $5,
		    status = $6,
		    assigned_to = $7,
		    notes = $8,
		    evidence_refs_json = $9,
		    completed_by = $10,
		    completed_at = $11,
		    updated_at = $12
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, engagement_id, wstg_id, category, title, status,
		          assigned_to, notes, evidence_refs_json,
		          completed_by, completed_at, created_by, created_at, updated_at
	`, current.TenantID, current.ID, current.WSTGID, current.Category, current.Title, current.Status,
		current.AssignedTo, current.Notes, evidenceJSON, current.CompletedBy, current.CompletedAt, current.UpdatedAt)

	updated, err := scanValidationManualTestCase(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationManualTestCase{}, false, nil
		}
		return models.ValidationManualTestCase{}, false, fmt.Errorf("update validation manual test: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.ValidationManualTestCase{}, false, fmt.Errorf("commit validation manual test update tx: %w", err)
	}

	return updated, true, nil
}

func scanValidationAttackTrace(row interface{ Scan(dest ...any) error }) (models.ValidationAttackTrace, error) {
	var (
		item          models.ValidationAttackTrace
		evidenceJSON  []byte
		artifactsJSON []byte
		replayJSON    []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.EngagementID,
		&item.ScanJobID,
		&item.TaskID,
		&item.AdapterID,
		&item.TargetKind,
		&item.Target,
		&item.Title,
		&item.Summary,
		&item.Severity,
		&evidenceJSON,
		&artifactsJSON,
		&replayJSON,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.ValidationAttackTrace{}, err
	}

	if len(evidenceJSON) > 0 {
		if err := json.Unmarshal(evidenceJSON, &item.EvidenceRefs); err != nil {
			return models.ValidationAttackTrace{}, fmt.Errorf("decode validation attack trace evidence refs: %w", err)
		}
	}
	if len(artifactsJSON) > 0 {
		if err := json.Unmarshal(artifactsJSON, &item.Artifacts); err != nil {
			return models.ValidationAttackTrace{}, fmt.Errorf("decode validation attack trace artifacts: %w", err)
		}
	}
	if len(replayJSON) > 0 {
		if err := json.Unmarshal(replayJSON, &item.ReplayManifest); err != nil {
			return models.ValidationAttackTrace{}, fmt.Errorf("decode validation attack trace replay manifest: %w", err)
		}
	}
	if item.Artifacts == nil {
		item.Artifacts = map[string]any{}
	}
	if item.ReplayManifest == nil {
		item.ReplayManifest = map[string]any{}
	}
	item.Severity = normalizeValidationTraceSeverity(item.Severity)
	item.AdapterID = strings.ToLower(strings.TrimSpace(item.AdapterID))
	item.TargetKind = strings.ToLower(strings.TrimSpace(item.TargetKind))
	item.EvidenceRefs = sanitizeValidationStringList(item.EvidenceRefs)

	return item, nil
}

func scanValidationManualTestCase(row interface{ Scan(dest ...any) error }) (models.ValidationManualTestCase, error) {
	var (
		item         models.ValidationManualTestCase
		evidenceJSON []byte
		completedAt  sql.NullTime
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.EngagementID,
		&item.WSTGID,
		&item.Category,
		&item.Title,
		&item.Status,
		&item.AssignedTo,
		&item.Notes,
		&evidenceJSON,
		&item.CompletedBy,
		&completedAt,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.ValidationManualTestCase{}, err
	}

	if len(evidenceJSON) > 0 {
		if err := json.Unmarshal(evidenceJSON, &item.EvidenceRefs); err != nil {
			return models.ValidationManualTestCase{}, fmt.Errorf("decode validation manual test evidence refs: %w", err)
		}
	}
	item.EvidenceRefs = sanitizeValidationStringList(item.EvidenceRefs)
	item.Status = normalizeValidationManualTestStatus(item.Status)
	item.WSTGID = strings.ToUpper(strings.TrimSpace(item.WSTGID))
	item.Category = strings.TrimSpace(item.Category)
	item.Title = strings.TrimSpace(item.Title)
	item.AssignedTo = strings.TrimSpace(item.AssignedTo)
	item.Notes = strings.TrimSpace(item.Notes)
	item.CompletedBy = strings.TrimSpace(item.CompletedBy)
	if completedAt.Valid {
		value := completedAt.Time.UTC()
		item.CompletedAt = &value
	}

	return item, nil
}

func normalizeValidationTraceSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		return "info"
	}
}

func normalizeValidationManualTestStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "not_started":
		return "not_started"
	case "in_progress":
		return "in_progress"
	case "passed":
		return "passed"
	case "failed":
		return "failed"
	case "not_applicable":
		return "not_applicable"
	case "blocked":
		return "blocked"
	default:
		return ""
	}
}

func isValidationManualTestCompleteStatus(status string) bool {
	switch normalizeValidationManualTestStatus(status) {
	case "passed", "failed", "not_applicable":
		return true
	default:
		return false
	}
}

func sanitizeValidationStringList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func cloneValidationMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		normalizedKey := strings.TrimSpace(key)
		if normalizedKey == "" {
			continue
		}
		out[normalizedKey] = value
	}
	return out
}

func nextValidationAttackTraceID() string {
	sequence := atomic.AddUint64(&validationAttackTraceSequence, 1)
	return fmt.Sprintf("validation-trace-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextValidationManualTestID() string {
	sequence := atomic.AddUint64(&validationManualTestSequence, 1)
	return fmt.Sprintf("validation-manual-test-%d-%06d", time.Now().UTC().Unix(), sequence)
}
