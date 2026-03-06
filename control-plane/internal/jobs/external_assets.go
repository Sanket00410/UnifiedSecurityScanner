package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListExternalAssetsForTenant(ctx context.Context, tenantID string, assetType string, limit int) ([]models.ExternalAsset, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 2000 {
		limit = 500
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, asset_type, value, source, metadata_json, first_seen_at, last_seen_at, created_at, updated_at
		FROM external_assets
		WHERE tenant_id = $1
		  AND ($2 = '' OR asset_type = $2)
		ORDER BY updated_at DESC, asset_type ASC, value ASC
		LIMIT $3
	`, tenantID, normalizeExternalAssetType(assetType), limit)
	if err != nil {
		return nil, fmt.Errorf("list external assets: %w", err)
	}
	defer rows.Close()

	out := make([]models.ExternalAsset, 0, limit)
	for rows.Next() {
		item, err := scanExternalAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate external assets: %w", err)
	}

	return out, nil
}

func (s *Store) UpsertExternalAssetForTenant(ctx context.Context, tenantID string, actor string, request models.UpsertExternalAssetRequest) (models.ExternalAsset, error) {
	tenantID = strings.TrimSpace(tenantID)
	assetType := normalizeExternalAssetType(request.AssetType)
	value := strings.ToLower(strings.TrimSpace(request.Value))
	if value == "" {
		return models.ExternalAsset{}, fmt.Errorf("value is required")
	}
	if assetType == "" {
		return models.ExternalAsset{}, fmt.Errorf("asset_type is required")
	}
	if !isSupportedExternalAssetType(assetType) {
		return models.ExternalAsset{}, fmt.Errorf("asset_type %q is not supported", assetType)
	}

	source := strings.TrimSpace(request.Source)
	if source == "" {
		source = "manual"
	}
	metadata := request.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	now := time.Now().UTC()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.ExternalAsset{}, fmt.Errorf("begin external asset upsert tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return models.ExternalAsset{}, fmt.Errorf("marshal external asset metadata: %w", err)
	}
	item := models.ExternalAsset{
		ID:          nextExternalAssetID(),
		TenantID:    tenantID,
		AssetType:   assetType,
		Value:       value,
		Source:      source,
		Metadata:    metadata,
		FirstSeenAt: now,
		LastSeenAt:  now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	returned, err := scanExternalAsset(tx.QueryRow(ctx, `
		INSERT INTO external_assets (
			id, tenant_id, asset_type, value, source, metadata_json,
			first_seen_at, last_seen_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10
		)
		ON CONFLICT (tenant_id, asset_type, value) DO UPDATE SET
			source = EXCLUDED.source,
			metadata_json = EXCLUDED.metadata_json,
			last_seen_at = EXCLUDED.last_seen_at,
			updated_at = EXCLUDED.updated_at
		RETURNING id, tenant_id, asset_type, value, source, metadata_json, first_seen_at, last_seen_at, created_at, updated_at
	`, item.ID, item.TenantID, item.AssetType, item.Value, item.Source, metadataJSON, item.FirstSeenAt, item.LastSeenAt, item.CreatedAt, item.UpdatedAt))
	if err != nil {
		return models.ExternalAsset{}, fmt.Errorf("upsert external asset: %w", err)
	}
	item = returned

	if err := publishPlatformEventTx(ctx, tx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "external_asset.upserted",
		SourceService: "control-plane",
		AggregateType: "external_asset",
		AggregateID:   item.ID,
		Payload: map[string]any{
			"asset_type": item.AssetType,
			"value":      item.Value,
			"source":     item.Source,
			"actor":      strings.TrimSpace(actor),
		},
		CreatedAt: now,
	}); err != nil {
		return models.ExternalAsset{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.ExternalAsset{}, fmt.Errorf("commit external asset upsert tx: %w", err)
	}

	return item, nil
}

func (s *Store) SyncExternalAssetsForTenant(ctx context.Context, tenantID string, actor string, request models.SyncExternalAssetsRequest) (models.SyncExternalAssetsResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	if len(request.Assets) == 0 {
		return models.SyncExternalAssetsResult{}, fmt.Errorf("assets must contain at least one item")
	}

	source := strings.TrimSpace(request.Source)
	if source == "" {
		source = "sync"
	}

	items := make([]models.ExternalAsset, 0, len(request.Assets))
	for _, incoming := range request.Assets {
		clone := incoming
		if strings.TrimSpace(clone.Source) == "" {
			clone.Source = source
		}
		item, err := s.UpsertExternalAssetForTenant(ctx, tenantID, actor, clone)
		if err != nil {
			return models.SyncExternalAssetsResult{}, err
		}
		items = append(items, item)
	}

	return models.SyncExternalAssetsResult{
		ImportedCount: len(items),
		Items:         items,
	}, nil
}

func scanExternalAsset(row interface{ Scan(dest ...any) error }) (models.ExternalAsset, error) {
	var (
		item         models.ExternalAsset
		metadataJSON []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.AssetType,
		&item.Value,
		&item.Source,
		&metadataJSON,
		&item.FirstSeenAt,
		&item.LastSeenAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.ExternalAsset{}, err
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &item.Metadata); err != nil {
			return models.ExternalAsset{}, fmt.Errorf("decode external asset metadata: %w", err)
		}
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}

	return item, nil
}

func normalizeExternalAssetType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isSupportedExternalAssetType(value string) bool {
	switch normalizeExternalAssetType(value) {
	case "domain", "subdomain", "ip", "service", "certificate":
		return true
	default:
		return false
	}
}

func nextExternalAssetID() string {
	sequence := atomic.AddUint64(&externalAssetSequence, 1)
	return fmt.Sprintf("external-asset-%d-%06d", time.Now().UTC().Unix(), sequence)
}
