package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
	"unifiedsecurityscanner/control-plane/internal/risk"
)

func (s *Store) GetAssetProfileForTenant(ctx context.Context, organizationID string, assetID string) (models.AssetProfile, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, asset_id, asset_type, asset_name, environment, exposure, criticality, owner_team, tags_json, created_at, updated_at
		FROM asset_profiles
		WHERE tenant_id = $1
		  AND asset_id = $2
	`, strings.TrimSpace(organizationID), strings.TrimSpace(assetID))

	profile, err := scanAssetProfile(row)
	if err != nil {
		if isNoRows(err) {
			return models.AssetProfile{}, false, nil
		}
		return models.AssetProfile{}, false, err
	}

	return profile, true, nil
}

func (s *Store) UpsertAssetProfileForTenant(ctx context.Context, organizationID string, assetID string, request models.UpsertAssetProfileRequest) (models.AssetProfile, error) {
	now := time.Now().UTC()
	profile := models.AssetProfile{
		TenantID:    strings.TrimSpace(organizationID),
		AssetID:     strings.TrimSpace(assetID),
		AssetType:   strings.TrimSpace(request.AssetType),
		AssetName:   strings.TrimSpace(request.AssetName),
		Environment: strings.ToLower(strings.TrimSpace(request.Environment)),
		Exposure:    strings.ToLower(strings.TrimSpace(request.Exposure)),
		Criticality: clampAssetScore(request.Criticality, 5),
		OwnerTeam:   strings.TrimSpace(request.OwnerTeam),
		Tags:        sanitizeStringSlice(request.Tags),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if profile.AssetType == "" {
		profile.AssetType = "unknown"
	}
	if profile.AssetName == "" {
		profile.AssetName = profile.AssetID
	}
	if profile.Environment == "" {
		profile.Environment = "production"
	}
	if profile.Exposure == "" {
		profile.Exposure = "internal"
	}

	tagsJSON, err := json.Marshal(profile.Tags)
	if err != nil {
		return models.AssetProfile{}, fmt.Errorf("marshal asset profile tags: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO asset_profiles (
			tenant_id, asset_id, asset_type, asset_name, environment, exposure, criticality, owner_team, tags_json, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10
		)
		ON CONFLICT (tenant_id, asset_id) DO UPDATE SET
			asset_type = EXCLUDED.asset_type,
			asset_name = EXCLUDED.asset_name,
			environment = EXCLUDED.environment,
			exposure = EXCLUDED.exposure,
			criticality = EXCLUDED.criticality,
			owner_team = EXCLUDED.owner_team,
			tags_json = EXCLUDED.tags_json,
			updated_at = EXCLUDED.updated_at
	`, profile.TenantID, profile.AssetID, profile.AssetType, profile.AssetName, profile.Environment, profile.Exposure, profile.Criticality, profile.OwnerTeam, tagsJSON, now)
	if err != nil {
		return models.AssetProfile{}, fmt.Errorf("upsert asset profile: %w", err)
	}

	return profile, nil
}

func (s *Store) ListCompensatingControlsForTenant(ctx context.Context, organizationID string, assetID string, limit int) ([]models.CompensatingControl, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, asset_id, name, control_type, scope_layer, effectiveness, enabled, notes, created_at, updated_at
		FROM compensating_controls
		WHERE tenant_id = $1
		  AND asset_id = $2
		ORDER BY updated_at DESC
		LIMIT $3
	`, strings.TrimSpace(organizationID), strings.TrimSpace(assetID), limit)
	if err != nil {
		return nil, fmt.Errorf("list compensating controls: %w", err)
	}
	defer rows.Close()

	out := make([]models.CompensatingControl, 0, limit)
	for rows.Next() {
		control, err := scanCompensatingControl(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, control)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate compensating controls: %w", err)
	}

	return out, nil
}

func (s *Store) CreateCompensatingControlForTenant(ctx context.Context, organizationID string, assetID string, request models.CreateCompensatingControlRequest) (models.CompensatingControl, error) {
	now := time.Now().UTC()
	control := models.CompensatingControl{
		ID:            nextControlID(),
		TenantID:      strings.TrimSpace(organizationID),
		AssetID:       strings.TrimSpace(assetID),
		Name:          strings.TrimSpace(request.Name),
		ControlType:   strings.ToLower(strings.TrimSpace(request.ControlType)),
		ScopeLayer:    strings.ToLower(strings.TrimSpace(request.ScopeLayer)),
		Effectiveness: clampAssetScore(request.Effectiveness, 5),
		Enabled:       request.Enabled,
		Notes:         strings.TrimSpace(request.Notes),
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if control.ScopeLayer == "" {
		control.ScopeLayer = "all"
	}
	if control.ControlType == "" {
		control.ControlType = "custom"
	}
	if !request.Enabled {
		control.Enabled = false
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO compensating_controls (
			id, tenant_id, asset_id, name, control_type, scope_layer, effectiveness, enabled, notes, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10
		)
	`, control.ID, control.TenantID, control.AssetID, control.Name, control.ControlType, control.ScopeLayer, control.Effectiveness, control.Enabled, control.Notes, now)
	if err != nil {
		return models.CompensatingControl{}, fmt.Errorf("create compensating control: %w", err)
	}

	return control, nil
}

type assetRiskEnvelope struct {
	profile    models.AssetProfile
	hasProfile bool
	controls   []models.CompensatingControl
}

func loadAssetRiskEnvelopeTx(ctx context.Context, tx pgx.Tx, tenantID string, assetID string) (assetRiskEnvelope, error) {
	envelope := assetRiskEnvelope{
		controls: make([]models.CompensatingControl, 0),
	}

	row := tx.QueryRow(ctx, `
		SELECT tenant_id, asset_id, asset_type, asset_name, environment, exposure, criticality, owner_team, tags_json, created_at, updated_at
		FROM asset_profiles
		WHERE tenant_id = $1
		  AND asset_id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(assetID))

	profile, err := scanAssetProfile(row)
	if err == nil {
		envelope.profile = profile
		envelope.hasProfile = true
	} else if !isNoRows(err) {
		return assetRiskEnvelope{}, err
	}

	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, asset_id, name, control_type, scope_layer, effectiveness, enabled, notes, created_at, updated_at
		FROM compensating_controls
		WHERE tenant_id = $1
		  AND asset_id = $2
		  AND enabled = TRUE
	`, strings.TrimSpace(tenantID), strings.TrimSpace(assetID))
	if err != nil {
		return assetRiskEnvelope{}, fmt.Errorf("load compensating controls: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		control, err := scanCompensatingControl(rows)
		if err != nil {
			return assetRiskEnvelope{}, err
		}
		envelope.controls = append(envelope.controls, control)
	}

	if err := rows.Err(); err != nil {
		return assetRiskEnvelope{}, fmt.Errorf("iterate compensating controls: %w", err)
	}

	return envelope, nil
}

func riskInputsForFinding(finding models.CanonicalFinding, envelope assetRiskEnvelope) risk.Inputs {
	inputs := risk.Inputs{}
	if envelope.hasProfile {
		inputs.EnvironmentOverride = envelope.profile.Environment
		inputs.ExposureOverride = envelope.profile.Exposure
		inputs.AssetCriticalityOverride = envelope.profile.Criticality
		inputs.OwnerTeam = envelope.profile.OwnerTeam
	}

	reduction := 0.0
	layer := strings.ToLower(strings.TrimSpace(finding.Source.Layer))
	if layer == "" {
		layer = risk.LayerForAdapter(finding.Scanner.AdapterID)
		if layer == "" {
			layer = risk.LayerForAdapter(finding.Source.Tool)
		}
	}
	for _, control := range envelope.controls {
		scope := strings.ToLower(strings.TrimSpace(control.ScopeLayer))
		if scope != "" && scope != "all" && scope != layer {
			continue
		}

		contribution := clampAssetScore(control.Effectiveness, 0) / 4
		switch strings.ToLower(strings.TrimSpace(control.ControlType)) {
		case "waf", "network_segmentation", "mfa":
			if layer == "dast" || layer == "pentest" {
				contribution *= 1.15
			}
		case "code_review", "branch_protection":
			if layer == "sast" || layer == "sca" || layer == "secrets" || layer == "iac" {
				contribution *= 1.10
			}
		}

		reduction += contribution
	}

	inputs.CompensatingControlReduction = clampAssetScore(reduction, 0)
	return inputs
}

func clampAssetScore(value float64, fallback float64) float64 {
	switch {
	case value <= 0:
		return fallback
	case value > 10:
		return 10
	default:
		return value
	}
}

func sanitizeStringSlice(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
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

type assetProfileScanner interface {
	Scan(dest ...any) error
}

func scanAssetProfile(scanner assetProfileScanner) (models.AssetProfile, error) {
	var profile models.AssetProfile
	var tagsJSON []byte

	err := scanner.Scan(
		&profile.TenantID,
		&profile.AssetID,
		&profile.AssetType,
		&profile.AssetName,
		&profile.Environment,
		&profile.Exposure,
		&profile.Criticality,
		&profile.OwnerTeam,
		&tagsJSON,
		&profile.CreatedAt,
		&profile.UpdatedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.AssetProfile{}, err
		}
		return models.AssetProfile{}, fmt.Errorf("scan asset profile: %w", err)
	}

	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &profile.Tags); err != nil {
			return models.AssetProfile{}, fmt.Errorf("decode asset profile tags: %w", err)
		}
	}

	return profile, nil
}

func scanCompensatingControl(scanner assetProfileScanner) (models.CompensatingControl, error) {
	var control models.CompensatingControl
	err := scanner.Scan(
		&control.ID,
		&control.TenantID,
		&control.AssetID,
		&control.Name,
		&control.ControlType,
		&control.ScopeLayer,
		&control.Effectiveness,
		&control.Enabled,
		&control.Notes,
		&control.CreatedAt,
		&control.UpdatedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.CompensatingControl{}, err
		}
		return models.CompensatingControl{}, fmt.Errorf("scan compensating control: %w", err)
	}

	return control, nil
}
