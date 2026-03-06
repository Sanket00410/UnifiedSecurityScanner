package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListAPIAssetsForTenant(ctx context.Context, tenantID string, limit int) ([]models.APIAsset, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			a.id,
			a.tenant_id,
			a.name,
			a.base_url,
			a.source,
			a.spec_version,
			a.spec_hash,
			a.created_by,
			COALESCE(COUNT(e.id), 0) AS endpoint_count,
			a.created_at,
			a.updated_at
		FROM api_assets a
		LEFT JOIN api_endpoints e ON e.api_asset_id = a.id AND e.tenant_id = a.tenant_id
		WHERE a.tenant_id = $1
		GROUP BY a.id, a.tenant_id, a.name, a.base_url, a.source, a.spec_version, a.spec_hash, a.created_by, a.created_at, a.updated_at
		ORDER BY a.updated_at DESC, a.name ASC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list api assets: %w", err)
	}
	defer rows.Close()

	out := make([]models.APIAsset, 0, limit)
	for rows.Next() {
		var item models.APIAsset
		if err := rows.Scan(
			&item.ID,
			&item.TenantID,
			&item.Name,
			&item.BaseURL,
			&item.Source,
			&item.SpecVersion,
			&item.SpecHash,
			&item.CreatedBy,
			&item.EndpointCount,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan api asset: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate api assets: %w", err)
	}

	return out, nil
}

func (s *Store) ListAPIEndpointsForTenant(ctx context.Context, tenantID string, apiAssetID string, limit int) ([]models.APIEndpoint, error) {
	tenantID = strings.TrimSpace(tenantID)
	apiAssetID = strings.TrimSpace(apiAssetID)
	if tenantID == "" || apiAssetID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, api_asset_id, tenant_id, path, method, operation_id, tags_json, auth_required, created_at
		FROM api_endpoints
		WHERE tenant_id = $1
		  AND api_asset_id = $2
		ORDER BY path ASC, method ASC
		LIMIT $3
	`, tenantID, apiAssetID, limit)
	if err != nil {
		return nil, fmt.Errorf("list api endpoints: %w", err)
	}
	defer rows.Close()

	out := make([]models.APIEndpoint, 0, limit)
	for rows.Next() {
		var (
			item     models.APIEndpoint
			tagsJSON []byte
		)
		if err := rows.Scan(
			&item.ID,
			&item.APIAssetID,
			&item.TenantID,
			&item.Path,
			&item.Method,
			&item.OperationID,
			&tagsJSON,
			&item.AuthRequired,
			&item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan api endpoint: %w", err)
		}
		if len(tagsJSON) > 0 {
			if err := json.Unmarshal(tagsJSON, &item.Tags); err != nil {
				return nil, fmt.Errorf("decode api endpoint tags: %w", err)
			}
		}
		if item.Tags == nil {
			item.Tags = []string{}
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate api endpoints: %w", err)
	}

	return out, nil
}

func (s *Store) ImportOpenAPIForTenant(ctx context.Context, tenantID string, actor string, request models.ImportOpenAPIRequest) (models.ImportedAPIAsset, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)

	name := strings.TrimSpace(request.Name)
	if name == "" {
		return models.ImportedAPIAsset{}, fmt.Errorf("name is required")
	}

	specVersion, endpoints, err := parseOpenAPIEndpoints(request.Spec)
	if err != nil {
		return models.ImportedAPIAsset{}, err
	}

	now := time.Now().UTC()
	baseURL := strings.TrimSpace(request.BaseURL)
	source := strings.TrimSpace(request.Source)
	if source == "" {
		source = "manual"
	}

	sum := sha256.Sum256(request.Spec)
	specHash := hex.EncodeToString(sum[:])

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.ImportedAPIAsset{}, fmt.Errorf("begin openapi import tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var asset models.APIAsset
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, name, base_url, source, spec_version, spec_hash, created_by, created_at, updated_at
		FROM api_assets
		WHERE tenant_id = $1 AND name = $2
		FOR UPDATE
	`, tenantID, name).Scan(
		&asset.ID,
		&asset.TenantID,
		&asset.Name,
		&asset.BaseURL,
		&asset.Source,
		&asset.SpecVersion,
		&asset.SpecHash,
		&asset.CreatedBy,
		&asset.CreatedAt,
		&asset.UpdatedAt,
	)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return models.ImportedAPIAsset{}, fmt.Errorf("load api asset for openapi import: %w", err)
	}

	if errors.Is(err, pgx.ErrNoRows) {
		asset = models.APIAsset{
			ID:          nextAPIAssetID(),
			TenantID:    tenantID,
			Name:        name,
			BaseURL:     baseURL,
			Source:      source,
			SpecVersion: specVersion,
			SpecHash:    specHash,
			CreatedBy:   actor,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO api_assets (
				id, tenant_id, name, base_url, source, spec_version, spec_hash, created_by, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $9
			)
		`, asset.ID, asset.TenantID, asset.Name, asset.BaseURL, asset.Source, asset.SpecVersion, asset.SpecHash, asset.CreatedBy, now)
		if err != nil {
			return models.ImportedAPIAsset{}, fmt.Errorf("insert api asset: %w", err)
		}
	} else {
		asset.BaseURL = baseURL
		asset.Source = source
		asset.SpecVersion = specVersion
		asset.SpecHash = specHash
		asset.UpdatedAt = now
		if asset.CreatedBy == "" {
			asset.CreatedBy = actor
		}
		_, err = tx.Exec(ctx, `
			UPDATE api_assets
			SET base_url = $3,
			    source = $4,
			    spec_version = $5,
			    spec_hash = $6,
			    updated_at = $7
			WHERE tenant_id = $1
			  AND id = $2
		`, asset.TenantID, asset.ID, asset.BaseURL, asset.Source, asset.SpecVersion, asset.SpecHash, asset.UpdatedAt)
		if err != nil {
			return models.ImportedAPIAsset{}, fmt.Errorf("update api asset: %w", err)
		}

		_, err = tx.Exec(ctx, `
			DELETE FROM api_endpoints
			WHERE tenant_id = $1
			  AND api_asset_id = $2
		`, tenantID, asset.ID)
		if err != nil {
			return models.ImportedAPIAsset{}, fmt.Errorf("clear existing api endpoints: %w", err)
		}
	}

	for _, endpoint := range endpoints {
		tagsJSON, err := json.Marshal(endpoint.Tags)
		if err != nil {
			return models.ImportedAPIAsset{}, fmt.Errorf("marshal api endpoint tags: %w", err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO api_endpoints (
				id, api_asset_id, tenant_id, path, method, operation_id, tags_json, auth_required, created_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9
			)
		`, nextAPIEndpointID(), asset.ID, tenantID, endpoint.Path, endpoint.Method, endpoint.OperationID, tagsJSON, endpoint.AuthRequired, now)
		if err != nil {
			return models.ImportedAPIAsset{}, fmt.Errorf("insert api endpoint: %w", err)
		}
	}

	if err := publishPlatformEventTx(ctx, tx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "api_asset.openapi_imported",
		SourceService: "control-plane",
		AggregateType: "api_asset",
		AggregateID:   asset.ID,
		Payload: map[string]any{
			"name":           asset.Name,
			"source":         asset.Source,
			"spec_version":   asset.SpecVersion,
			"endpoint_count": len(endpoints),
		},
		CreatedAt: now,
	}); err != nil {
		return models.ImportedAPIAsset{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.ImportedAPIAsset{}, fmt.Errorf("commit openapi import tx: %w", err)
	}

	asset.EndpointCount = int64(len(endpoints))
	return models.ImportedAPIAsset{
		Asset:         asset,
		EndpointCount: int64(len(endpoints)),
	}, nil
}

type discoveredOpenAPIEndpoint struct {
	Path         string
	Method       string
	OperationID  string
	Tags         []string
	AuthRequired bool
}

func parseOpenAPIEndpoints(raw json.RawMessage) (string, []discoveredOpenAPIEndpoint, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "", nil, fmt.Errorf("spec is required")
	}

	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return "", nil, fmt.Errorf("spec must be valid OpenAPI JSON")
	}

	specVersion := strings.TrimSpace(toString(root["openapi"]))
	if specVersion == "" {
		specVersion = strings.TrimSpace(toString(root["swagger"]))
	}

	pathsObject, ok := root["paths"].(map[string]any)
	if !ok || len(pathsObject) == 0 {
		return specVersion, []discoveredOpenAPIEndpoint{}, nil
	}

	defaultAuthRequired := false
	if securityArray, ok := root["security"].([]any); ok && len(securityArray) > 0 {
		defaultAuthRequired = true
	}

	methodWhitelist := []string{"get", "post", "put", "patch", "delete", "head", "options", "trace"}
	dedup := make(map[string]struct{})
	out := make([]discoveredOpenAPIEndpoint, 0, len(pathsObject))

	for rawPath, item := range pathsObject {
		path := strings.TrimSpace(rawPath)
		if path == "" {
			continue
		}

		operations, ok := item.(map[string]any)
		if !ok {
			continue
		}

		for rawMethod, operationRaw := range operations {
			methodLower := strings.ToLower(strings.TrimSpace(rawMethod))
			if !slices.Contains(methodWhitelist, methodLower) {
				continue
			}

			operationMap, ok := operationRaw.(map[string]any)
			if !ok {
				operationMap = map[string]any{}
			}

			authRequired := defaultAuthRequired
			if opSecurity, present := operationMap["security"]; present {
				if opArray, ok := opSecurity.([]any); ok {
					authRequired = len(opArray) > 0
				}
			}

			key := strings.ToUpper(methodLower) + " " + path
			if _, exists := dedup[key]; exists {
				continue
			}
			dedup[key] = struct{}{}

			out = append(out, discoveredOpenAPIEndpoint{
				Path:         path,
				Method:       strings.ToUpper(methodLower),
				OperationID:  strings.TrimSpace(toString(operationMap["operationId"])),
				Tags:         normalizeStringList(toStringSlice(operationMap["tags"])),
				AuthRequired: authRequired,
			})
		}
	}

	slices.SortFunc(out, func(a, b discoveredOpenAPIEndpoint) int {
		left := a.Path + ":" + a.Method
		right := b.Path + ":" + b.Method
		return strings.Compare(left, right)
	})

	return specVersion, out, nil
}

func toString(value any) string {
	item, _ := value.(string)
	return item
}

func toStringSlice(value any) []string {
	array, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(array))
	for _, entry := range array {
		text := strings.TrimSpace(toString(entry))
		if text == "" {
			continue
		}
		out = append(out, text)
	}
	return out
}

func nextAPIAssetID() string {
	sequence := atomic.AddUint64(&apiAssetSequence, 1)
	return fmt.Sprintf("api-asset-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextAPIEndpointID() string {
	sequence := atomic.AddUint64(&apiEndpointSequence, 1)
	return fmt.Sprintf("api-endpoint-%d-%06d", time.Now().UTC().Unix(), sequence)
}
