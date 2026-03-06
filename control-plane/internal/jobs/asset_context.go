package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) CreateAssetContextEventForTenant(ctx context.Context, tenantID string, actor string, request models.CreateAssetContextEventRequest) (models.AssetContextEvent, error) {
	tenantID = strings.TrimSpace(tenantID)
	assetID := strings.TrimSpace(request.AssetID)
	assetType := strings.ToLower(strings.TrimSpace(request.AssetType))
	eventKind := normalizeAssetContextEventKind(request.EventKind)
	if tenantID == "" {
		return models.AssetContextEvent{}, fmt.Errorf("tenant_id is required")
	}
	if assetID == "" {
		return models.AssetContextEvent{}, fmt.Errorf("asset_id is required")
	}
	if assetType == "" {
		return models.AssetContextEvent{}, fmt.Errorf("asset_type is required")
	}
	if eventKind == "" {
		return models.AssetContextEvent{}, fmt.Errorf("event_kind is required")
	}

	source := strings.TrimSpace(request.Source)
	if source == "" {
		source = strings.TrimSpace(actor)
	}
	if source == "" {
		source = "manual"
	}

	metadata := request.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	now := time.Now().UTC()
	platformEvent := normalizePlatformEvent(models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "asset_context." + eventKind,
		SourceService: "control-plane",
		AggregateType: "asset",
		AggregateID:   assetID,
		Payload: map[string]any{
			"asset_id":   assetID,
			"asset_type": assetType,
			"event_kind": eventKind,
			"source":     source,
			"metadata":   metadata,
		},
		CreatedAt: now,
	})

	if err := s.publishPlatformEvent(ctx, platformEvent); err != nil {
		return models.AssetContextEvent{}, fmt.Errorf("create asset context event: %w", err)
	}

	return assetContextEventFromPlatformEvent(platformEvent), nil
}

func (s *Store) ListAssetContextEventsForTenant(ctx context.Context, tenantID string, assetID string, eventKind string, limit int) ([]models.AssetContextEvent, error) {
	tenantID = strings.TrimSpace(tenantID)
	assetID = strings.TrimSpace(assetID)
	eventKind = normalizeAssetContextEventKind(eventKind)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	eventType := ""
	if eventKind != "" {
		eventType = "asset_context." + eventKind
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, event_type, source_service, aggregate_type, aggregate_id, payload_json, created_at
		FROM platform_events
		WHERE tenant_id = $1
		  AND aggregate_type = 'asset'
		  AND event_type LIKE 'asset_context.%'
		  AND ($2 = '' OR aggregate_id = $2)
		  AND ($3 = '' OR event_type = $3)
		ORDER BY created_at DESC, id DESC
		LIMIT $4
	`, tenantID, assetID, eventType, limit)
	if err != nil {
		return nil, fmt.Errorf("list asset context events: %w", err)
	}
	defer rows.Close()

	out := make([]models.AssetContextEvent, 0, limit)
	for rows.Next() {
		event, err := scanPlatformEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan asset context event row: %w", err)
		}
		out = append(out, assetContextEventFromPlatformEvent(event))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset context events: %w", err)
	}

	return out, nil
}

func assetContextEventFromPlatformEvent(event models.PlatformEvent) models.AssetContextEvent {
	metadata, _ := event.Payload["metadata"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
	}

	assetID := strings.TrimSpace(toString(event.Payload["asset_id"]))
	if assetID == "" {
		assetID = strings.TrimSpace(event.AggregateID)
	}

	assetType := strings.TrimSpace(strings.ToLower(toString(event.Payload["asset_type"])))
	source := strings.TrimSpace(toString(event.Payload["source"]))
	eventKind := normalizeAssetContextEventKind(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(event.EventType)), "asset_context."))

	return models.AssetContextEvent{
		ID:        event.ID,
		TenantID:  event.TenantID,
		AssetID:   assetID,
		AssetType: assetType,
		EventKind: eventKind,
		Source:    source,
		Metadata:  metadata,
		CreatedAt: event.CreatedAt,
	}
}

func normalizeAssetContextEventKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "build":
		return "build"
	case "deploy", "deployment":
		return "deploy"
	case "runtime", "run":
		return "runtime"
	case "artifact":
		return "artifact"
	case "ci", "pipeline":
		return "ci"
	default:
		return ""
	}
}
