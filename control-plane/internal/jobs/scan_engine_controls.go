package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListScanEngineControlsForTenant(ctx context.Context, tenantID string, targetKind string, limit int) ([]models.ScanEngineControl, error) {
	tenantID = strings.TrimSpace(tenantID)
	targetKind = normalizeEngineControlTargetKind(targetKind)
	if tenantID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 2000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id, adapter_id, target_kind, enabled, rulepack_version, max_runtime_seconds, updated_by, updated_at
		FROM scan_engine_controls
		WHERE tenant_id = $1
		  AND ($2 = '' OR target_kind = $2)
		ORDER BY adapter_id ASC, target_kind ASC
		LIMIT $3
	`, tenantID, targetKind, limit)
	if err != nil {
		return nil, fmt.Errorf("list scan engine controls: %w", err)
	}
	defer rows.Close()

	items := make([]models.ScanEngineControl, 0, limit)
	for rows.Next() {
		item, err := scanEngineControl(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan engine controls: %w", err)
	}

	return items, nil
}

func (s *Store) UpsertScanEngineControlForTenant(ctx context.Context, tenantID string, adapterID string, actor string, request models.UpsertScanEngineControlRequest) (models.ScanEngineControl, error) {
	tenantID = strings.TrimSpace(tenantID)
	adapterID = normalizeEngineControlAdapter(adapterID)
	targetKind := normalizeEngineControlTargetKind(request.TargetKind)
	actor = strings.TrimSpace(actor)

	if tenantID == "" {
		return models.ScanEngineControl{}, fmt.Errorf("tenant_id is required")
	}
	if adapterID == "" {
		return models.ScanEngineControl{}, fmt.Errorf("adapter_id is required")
	}
	if request.MaxRuntimeSeconds != nil && *request.MaxRuntimeSeconds < 0 {
		return models.ScanEngineControl{}, fmt.Errorf("max_runtime_seconds must be greater than or equal to zero")
	}

	existing, found, err := s.getScanEngineControlForTenant(ctx, tenantID, adapterID, targetKind)
	if err != nil {
		return models.ScanEngineControl{}, err
	}

	now := time.Now().UTC()
	item := models.ScanEngineControl{
		TenantID:          tenantID,
		AdapterID:         adapterID,
		TargetKind:        targetKind,
		Enabled:           true,
		RulepackVersion:   "",
		MaxRuntimeSeconds: 0,
		UpdatedBy:         actor,
		UpdatedAt:         now,
	}

	if found {
		item = existing
		item.UpdatedBy = actor
		item.UpdatedAt = now
	}

	if request.Enabled != nil {
		item.Enabled = *request.Enabled
	}
	if request.RulepackVersion != nil {
		item.RulepackVersion = strings.TrimSpace(*request.RulepackVersion)
	}
	if request.MaxRuntimeSeconds != nil {
		item.MaxRuntimeSeconds = *request.MaxRuntimeSeconds
	}
	if item.UpdatedBy == "" {
		item.UpdatedBy = "system"
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO scan_engine_controls (
			tenant_id, adapter_id, target_kind, enabled, rulepack_version, max_runtime_seconds, updated_by, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
		ON CONFLICT (tenant_id, adapter_id, target_kind) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			rulepack_version = EXCLUDED.rulepack_version,
			max_runtime_seconds = EXCLUDED.max_runtime_seconds,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
		RETURNING tenant_id, adapter_id, target_kind, enabled, rulepack_version, max_runtime_seconds, updated_by, updated_at
	`, item.TenantID, item.AdapterID, item.TargetKind, item.Enabled, item.RulepackVersion, item.MaxRuntimeSeconds, item.UpdatedBy, item.UpdatedAt)

	updated, err := scanEngineControl(row)
	if err != nil {
		return models.ScanEngineControl{}, fmt.Errorf("upsert scan engine control: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      updated.TenantID,
		EventType:     "scan_engine_control.updated",
		SourceService: "control-plane",
		AggregateType: "scan_engine_control",
		AggregateID:   updated.AdapterID + ":" + normalizeEngineControlTargetKind(updated.TargetKind),
		Payload: map[string]any{
			"adapter_id":          updated.AdapterID,
			"target_kind":         updated.TargetKind,
			"enabled":             updated.Enabled,
			"rulepack_version":    updated.RulepackVersion,
			"max_runtime_seconds": updated.MaxRuntimeSeconds,
			"updated_by":          updated.UpdatedBy,
		},
		CreatedAt: updated.UpdatedAt,
	})

	return updated, nil
}

func (s *Store) getScanEngineControlForTenant(ctx context.Context, tenantID string, adapterID string, targetKind string) (models.ScanEngineControl, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, adapter_id, target_kind, enabled, rulepack_version, max_runtime_seconds, updated_by, updated_at
		FROM scan_engine_controls
		WHERE tenant_id = $1
		  AND adapter_id = $2
		  AND target_kind = $3
	`, strings.TrimSpace(tenantID), normalizeEngineControlAdapter(adapterID), normalizeEngineControlTargetKind(targetKind))

	item, err := scanEngineControl(row)
	if err != nil {
		if isNoRows(err) {
			return models.ScanEngineControl{}, false, nil
		}
		return models.ScanEngineControl{}, false, fmt.Errorf("select scan engine control: %w", err)
	}
	return item, true, nil
}

func loadEffectiveScanEngineControlsTx(ctx context.Context, tx pgx.Tx, tenantID string, targetKind string, tools []string) (map[string]models.ScanEngineControl, error) {
	if len(tools) == 0 {
		return map[string]models.ScanEngineControl{}, nil
	}

	targetKind = normalizeEngineControlTargetKind(targetKind)
	scopeKinds := []string{""}
	if targetKind != "" {
		scopeKinds = append(scopeKinds, targetKind)
	}

	rows, err := tx.Query(ctx, `
		SELECT tenant_id, adapter_id, target_kind, enabled, rulepack_version, max_runtime_seconds, updated_by, updated_at
		FROM scan_engine_controls
		WHERE tenant_id = $1
		  AND adapter_id = ANY($2)
		  AND target_kind = ANY($3)
		ORDER BY adapter_id ASC,
		         CASE WHEN target_kind = $4 THEN 0 ELSE 1 END,
		         updated_at DESC
	`, strings.TrimSpace(tenantID), tools, scopeKinds, targetKind)
	if err != nil {
		return nil, fmt.Errorf("list effective scan engine controls: %w", err)
	}
	defer rows.Close()

	out := make(map[string]models.ScanEngineControl, len(tools))
	for rows.Next() {
		item, err := scanEngineControl(rows)
		if err != nil {
			return nil, err
		}
		if _, exists := out[item.AdapterID]; exists {
			continue
		}
		out[item.AdapterID] = item
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate effective scan engine controls: %w", err)
	}

	return out, nil
}

func scanEngineControl(row interface{ Scan(dest ...any) error }) (models.ScanEngineControl, error) {
	var item models.ScanEngineControl
	err := row.Scan(
		&item.TenantID,
		&item.AdapterID,
		&item.TargetKind,
		&item.Enabled,
		&item.RulepackVersion,
		&item.MaxRuntimeSeconds,
		&item.UpdatedBy,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.ScanEngineControl{}, err
	}

	item.TenantID = strings.TrimSpace(item.TenantID)
	item.AdapterID = normalizeEngineControlAdapter(item.AdapterID)
	item.TargetKind = normalizeEngineControlTargetKind(item.TargetKind)
	item.RulepackVersion = strings.TrimSpace(item.RulepackVersion)
	item.UpdatedBy = strings.TrimSpace(item.UpdatedBy)
	if item.MaxRuntimeSeconds < 0 {
		item.MaxRuntimeSeconds = 0
	}
	return item, nil
}

func normalizeEngineControlAdapter(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeEngineControlTargetKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "all", "*", "global":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}
