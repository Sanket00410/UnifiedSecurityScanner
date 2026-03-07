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

func (s *Store) ListScanPresetsForTenant(_ context.Context, _ string) ([]models.ScanPreset, error) {
	presets := []models.ScanPreset{
		{
			ID:          "repo-balanced",
			Name:        "Repository Balanced",
			Description: "General codebase baseline for SAST, SCA, secrets, and IaC checks.",
			TargetKind:  "repo",
			Profile:     "balanced",
			Tools:       defaultToolsForTargetKind("repo"),
		},
		{
			ID:          "repo-fast",
			Name:        "Repository Fast",
			Description: "Fast developer loop for common code and secret issues.",
			TargetKind:  "repo",
			Profile:     "fast",
			Tools:       []string{"semgrep", "gitleaks", "trivy"},
		},
		{
			ID:          "runtime-web",
			Name:        "Runtime Web Validation",
			Description: "Authenticated runtime checks for web/API targets.",
			TargetKind:  "url",
			Profile:     "runtime",
			Tools:       []string{"zap", "nuclei", "browser-probe"},
		},
		{
			ID:          "infrastructure-terraform",
			Name:        "Terraform IaC",
			Description: "Terraform-focused IaC posture checks.",
			TargetKind:  "terraform",
			Profile:     "iac",
			Tools:       defaultToolsForTargetKind("terraform"),
		},
		{
			ID:          "host-network",
			Name:        "Host Network Validation",
			Description: "Controlled network discovery and exposure checks.",
			TargetKind:  "host",
			Profile:     "network",
			Tools:       defaultToolsForTargetKind("host"),
		},
	}

	return presets, nil
}

func (s *Store) ListScanTargetsForTenant(ctx context.Context, tenantID string, limit int) ([]models.ScanTarget, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, target_kind, target, profile, tools, labels_json,
		       created_by, last_run_at, created_at, updated_at
		FROM scan_targets
		WHERE tenant_id = $1
		ORDER BY updated_at DESC, name ASC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list scan targets: %w", err)
	}
	defer rows.Close()

	items := make([]models.ScanTarget, 0, limit)
	for rows.Next() {
		target, err := scanTargetFromRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan scan target row: %w", err)
		}
		items = append(items, target)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan targets: %w", err)
	}

	return items, nil
}

func (s *Store) GetScanTargetForTenant(ctx context.Context, tenantID string, targetID string) (models.ScanTarget, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, target_kind, target, profile, tools, labels_json,
		       created_by, last_run_at, created_at, updated_at
		FROM scan_targets
		WHERE tenant_id = $1 AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID))

	item, err := scanTargetFromRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ScanTarget{}, false, nil
		}
		return models.ScanTarget{}, false, fmt.Errorf("select scan target: %w", err)
	}

	return item, true, nil
}

func (s *Store) CreateScanTargetForTenant(ctx context.Context, tenantID string, actor string, request models.CreateScanTargetRequest) (models.ScanTarget, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	now := time.Now().UTC()

	if err := s.enforceScanTargetLimit(ctx, tenantID); err != nil {
		return models.ScanTarget{}, err
	}

	target := normalizeCreateScanTargetRequest(tenantID, actor, request, now)
	labelsJSON, err := json.Marshal(target.Labels)
	if err != nil {
		return models.ScanTarget{}, fmt.Errorf("marshal scan target labels: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO scan_targets (
			id, tenant_id, name, target_kind, target, profile, tools, labels_json,
			created_by, last_run_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, NULL, $10, $10
		)
	`, target.ID, target.TenantID, target.Name, target.TargetKind, target.Target, target.Profile, target.Tools, labelsJSON,
		target.CreatedBy, now)
	if err != nil {
		return models.ScanTarget{}, fmt.Errorf("insert scan target: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      target.TenantID,
		EventType:     "scan_target.created",
		SourceService: "control-plane",
		AggregateType: "scan_target",
		AggregateID:   target.ID,
		Payload: map[string]any{
			"name":        target.Name,
			"target_kind": target.TargetKind,
			"profile":     target.Profile,
			"tool_count":  len(target.Tools),
		},
		CreatedAt: now,
	})

	return target, nil
}

func (s *Store) UpdateScanTargetForTenant(ctx context.Context, tenantID string, targetID string, request models.UpdateScanTargetRequest) (models.ScanTarget, bool, error) {
	existing, found, err := s.GetScanTargetForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.ScanTarget{}, false, err
	}
	if !found {
		return models.ScanTarget{}, false, nil
	}

	now := time.Now().UTC()
	updated := normalizeUpdateScanTargetRequest(existing, request, now)
	labelsJSON, err := json.Marshal(updated.Labels)
	if err != nil {
		return models.ScanTarget{}, false, fmt.Errorf("marshal scan target labels: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE scan_targets
		SET name = $3,
		    target_kind = $4,
		    target = $5,
		    profile = $6,
		    tools = $7,
		    labels_json = $8,
		    updated_at = $9
		WHERE tenant_id = $1 AND id = $2
		RETURNING id, tenant_id, name, target_kind, target, profile, tools, labels_json,
		          created_by, last_run_at, created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID), updated.Name, updated.TargetKind, updated.Target, updated.Profile, updated.Tools, labelsJSON, now)

	item, err := scanTargetFromRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ScanTarget{}, false, nil
		}
		return models.ScanTarget{}, false, fmt.Errorf("update scan target: %w", err)
	}

	return item, true, nil
}

func (s *Store) DeleteScanTargetForTenant(ctx context.Context, tenantID string, targetID string) (bool, error) {
	command, err := s.pool.Exec(ctx, `
		DELETE FROM scan_targets
		WHERE tenant_id = $1 AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID))
	if err != nil {
		return false, fmt.Errorf("delete scan target: %w", err)
	}
	deleted := command.RowsAffected() > 0
	if deleted {
		_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
			TenantID:      strings.TrimSpace(tenantID),
			EventType:     "scan_target.deleted",
			SourceService: "control-plane",
			AggregateType: "scan_target",
			AggregateID:   strings.TrimSpace(targetID),
			Payload:       map[string]any{},
			CreatedAt:     time.Now().UTC(),
		})
	}
	return deleted, nil
}

func (s *Store) RunScanTargetForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.RunScanTargetRequest) (models.ScanTarget, models.ScanJob, bool, error) {
	target, found, err := s.GetScanTargetForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.ScanTarget{}, models.ScanJob{}, false, err
	}
	if !found {
		return models.ScanTarget{}, models.ScanJob{}, false, nil
	}

	profile := strings.TrimSpace(request.Profile)
	if profile == "" {
		profile = target.Profile
	}
	if profile == "" {
		profile = "balanced"
	}

	tools := sanitizeTools(request.Tools)
	if len(tools) == 0 {
		tools = target.Tools
	}
	if len(tools) == 0 {
		tools = defaultToolsForTargetKind(target.TargetKind)
	}

	taskLabels := map[string]string{}
	for key, value := range request.TaskLabels {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		normalizedValue := strings.TrimSpace(value)
		if normalizedKey == "" || normalizedValue == "" {
			continue
		}
		taskLabels[normalizedKey] = normalizedValue
	}
	if value := strings.TrimSpace(stringLabelFromAny(target.Labels["validation_engagement_id"])); value != "" {
		taskLabels["validation_engagement_id"] = value
	}
	if value := strings.TrimSpace(request.ValidationEngagementID); value != "" {
		taskLabels["validation_engagement_id"] = value
	}
	if len(taskLabels) == 0 {
		taskLabels = nil
	}

	job, err := s.CreateForTenant(ctx, strings.TrimSpace(tenantID), models.CreateScanJobRequest{
		TenantID:    strings.TrimSpace(tenantID),
		TargetKind:  target.TargetKind,
		Target:      target.Target,
		Profile:     profile,
		RequestedBy: strings.TrimSpace(actor),
		Tools:       tools,
		TaskLabels:  taskLabels,
	})
	if err != nil {
		return models.ScanTarget{}, models.ScanJob{}, true, err
	}

	now := time.Now().UTC()
	row := s.pool.QueryRow(ctx, `
		UPDATE scan_targets
		SET last_run_at = $3,
		    updated_at = $3
		WHERE tenant_id = $1 AND id = $2
		RETURNING id, tenant_id, name, target_kind, target, profile, tools, labels_json,
		          created_by, last_run_at, created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID), now)

	updatedTarget, err := scanTargetFromRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ScanTarget{}, models.ScanJob{}, false, nil
		}
		return models.ScanTarget{}, models.ScanJob{}, true, fmt.Errorf("update scan target run timestamp: %w", err)
	}

	return updatedTarget, job, true, nil
}

func normalizeCreateScanTargetRequest(tenantID string, actor string, request models.CreateScanTargetRequest, now time.Time) models.ScanTarget {
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = "Unnamed Scan Target"
	}

	targetKind := strings.ToLower(strings.TrimSpace(request.TargetKind))
	target := strings.TrimSpace(request.Target)
	profile := strings.TrimSpace(request.Profile)
	if profile == "" {
		profile = "balanced"
	}

	tools := sanitizeTools(request.Tools)
	if len(tools) == 0 {
		tools = defaultToolsForTargetKind(targetKind)
	}

	labels := request.Labels
	if labels == nil {
		labels = map[string]any{}
	}

	return models.ScanTarget{
		ID:         nextScanTargetID(),
		TenantID:   tenantID,
		Name:       name,
		TargetKind: targetKind,
		Target:     target,
		Profile:    profile,
		Tools:      tools,
		Labels:     labels,
		CreatedBy:  actor,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

func normalizeUpdateScanTargetRequest(existing models.ScanTarget, request models.UpdateScanTargetRequest, now time.Time) models.ScanTarget {
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = existing.Name
	}

	targetKind := strings.ToLower(strings.TrimSpace(request.TargetKind))
	if targetKind == "" {
		targetKind = existing.TargetKind
	}

	target := strings.TrimSpace(request.Target)
	if target == "" {
		target = existing.Target
	}

	profile := strings.TrimSpace(request.Profile)
	if profile == "" {
		profile = existing.Profile
	}
	if profile == "" {
		profile = "balanced"
	}

	tools := sanitizeTools(request.Tools)
	if len(tools) == 0 {
		tools = existing.Tools
	}
	if len(tools) == 0 {
		tools = defaultToolsForTargetKind(targetKind)
	}

	labels := request.Labels
	if labels == nil {
		labels = existing.Labels
	}
	if labels == nil {
		labels = map[string]any{}
	}

	existing.Name = name
	existing.TargetKind = targetKind
	existing.Target = target
	existing.Profile = profile
	existing.Tools = tools
	existing.Labels = labels
	existing.UpdatedAt = now
	return existing
}

func scanTargetFromRow(row interface{ Scan(dest ...any) error }) (models.ScanTarget, error) {
	var (
		target     models.ScanTarget
		labelsJSON []byte
		lastRunAt  *time.Time
	)

	err := row.Scan(
		&target.ID,
		&target.TenantID,
		&target.Name,
		&target.TargetKind,
		&target.Target,
		&target.Profile,
		&target.Tools,
		&labelsJSON,
		&target.CreatedBy,
		&lastRunAt,
		&target.CreatedAt,
		&target.UpdatedAt,
	)
	if err != nil {
		return models.ScanTarget{}, err
	}

	target.LastRunAt = lastRunAt
	if len(labelsJSON) > 0 {
		if err := json.Unmarshal(labelsJSON, &target.Labels); err != nil {
			return models.ScanTarget{}, fmt.Errorf("decode scan target labels: %w", err)
		}
	}
	if target.Labels == nil {
		target.Labels = map[string]any{}
	}

	return target, nil
}

func nextScanTargetID() string {
	sequence := atomic.AddUint64(&scanTargetSequence, 1)
	return fmt.Sprintf("scan-target-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func stringLabelFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return ""
	}
}
