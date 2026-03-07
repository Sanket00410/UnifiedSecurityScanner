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

func (s *Store) ListRuntimeTelemetryConnectorsForTenant(ctx context.Context, tenantID string, connectorType string, limit int) ([]models.RuntimeTelemetryConnector, error) {
	tenantID = strings.TrimSpace(tenantID)
	connectorType = normalizeRuntimeTelemetryConnectorType(connectorType)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, connector_type, status, config_json,
		       last_sync_at, created_by, updated_by, created_at, updated_at
		FROM runtime_telemetry_connectors
		WHERE tenant_id = $1
		  AND ($2 = '' OR connector_type = $2)
		ORDER BY updated_at DESC, id DESC
		LIMIT $3
	`, tenantID, connectorType, limit)
	if err != nil {
		return nil, fmt.Errorf("list runtime telemetry connectors: %w", err)
	}
	defer rows.Close()

	items := make([]models.RuntimeTelemetryConnector, 0, limit)
	for rows.Next() {
		item, err := scanRuntimeTelemetryConnector(rows)
		if err != nil {
			return nil, fmt.Errorf("scan runtime telemetry connector row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runtime telemetry connector rows: %w", err)
	}
	return items, nil
}

func (s *Store) GetRuntimeTelemetryConnectorForTenant(ctx context.Context, tenantID string, connectorID string) (models.RuntimeTelemetryConnector, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	connectorID = strings.TrimSpace(connectorID)
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, connector_type, status, config_json,
		       last_sync_at, created_by, updated_by, created_at, updated_at
		FROM runtime_telemetry_connectors
		WHERE tenant_id = $1
		  AND id = $2
	`, tenantID, connectorID)
	item, err := scanRuntimeTelemetryConnector(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.RuntimeTelemetryConnector{}, false, nil
		}
		return models.RuntimeTelemetryConnector{}, false, fmt.Errorf("get runtime telemetry connector: %w", err)
	}
	return item, true, nil
}

func (s *Store) CreateRuntimeTelemetryConnectorForTenant(ctx context.Context, tenantID string, actor string, request models.CreateRuntimeTelemetryConnectorRequest) (models.RuntimeTelemetryConnector, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	name := strings.TrimSpace(request.Name)
	if name == "" {
		return models.RuntimeTelemetryConnector{}, fmt.Errorf("name is required")
	}
	connectorType := normalizeRuntimeTelemetryConnectorType(request.ConnectorType)
	if connectorType == "" {
		return models.RuntimeTelemetryConnector{}, fmt.Errorf("connector_type is required")
	}
	status := normalizeRuntimeTelemetryConnectorStatus(request.Status)
	if status == "" {
		status = "draft"
	}

	now := time.Now().UTC()
	item := models.RuntimeTelemetryConnector{
		ID:            nextRuntimeTelemetryConnectorID(),
		TenantID:      tenantID,
		Name:          name,
		ConnectorType: connectorType,
		Status:        status,
		Config:        cloneRuntimeTelemetryMap(request.Config),
		CreatedBy:     actor,
		UpdatedBy:     actor,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	configJSON, err := json.Marshal(item.Config)
	if err != nil {
		return models.RuntimeTelemetryConnector{}, fmt.Errorf("marshal runtime telemetry connector config: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO runtime_telemetry_connectors (
			id, tenant_id, name, connector_type, status, config_json,
			last_sync_at, created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			NULL, $7, $7, $8, $8
		)
		RETURNING id, tenant_id, name, connector_type, status, config_json,
		          last_sync_at, created_by, updated_by, created_at, updated_at
	`, item.ID, item.TenantID, item.Name, item.ConnectorType, item.Status, configJSON, item.CreatedBy, item.CreatedAt)

	created, err := scanRuntimeTelemetryConnector(row)
	if err != nil {
		return models.RuntimeTelemetryConnector{}, fmt.Errorf("create runtime telemetry connector: %w", err)
	}
	return created, nil
}

func (s *Store) UpdateRuntimeTelemetryConnectorForTenant(ctx context.Context, tenantID string, connectorID string, actor string, request models.UpdateRuntimeTelemetryConnectorRequest) (models.RuntimeTelemetryConnector, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	connectorID = strings.TrimSpace(connectorID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	current, found, err := s.GetRuntimeTelemetryConnectorForTenant(ctx, tenantID, connectorID)
	if err != nil || !found {
		return models.RuntimeTelemetryConnector{}, found, err
	}

	if value := strings.TrimSpace(request.Name); value != "" {
		current.Name = value
	}
	if value := normalizeRuntimeTelemetryConnectorType(request.ConnectorType); value != "" {
		current.ConnectorType = value
	}
	if value := normalizeRuntimeTelemetryConnectorStatus(request.Status); value != "" {
		current.Status = value
	}
	if request.Config != nil {
		current.Config = cloneRuntimeTelemetryMap(request.Config)
	}
	if request.LastSyncAt != nil {
		current.LastSyncAt = request.LastSyncAt
	}
	current.UpdatedBy = actor
	current.UpdatedAt = time.Now().UTC()

	configJSON, err := json.Marshal(current.Config)
	if err != nil {
		return models.RuntimeTelemetryConnector{}, true, fmt.Errorf("marshal runtime telemetry connector update config: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE runtime_telemetry_connectors
		SET name = $3,
		    connector_type = $4,
		    status = $5,
		    config_json = $6,
		    last_sync_at = $7,
		    updated_by = $8,
		    updated_at = $9
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, name, connector_type, status, config_json,
		          last_sync_at, created_by, updated_by, created_at, updated_at
	`, tenantID, connectorID, current.Name, current.ConnectorType, current.Status, configJSON, current.LastSyncAt,
		current.UpdatedBy, current.UpdatedAt)

	updated, err := scanRuntimeTelemetryConnector(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.RuntimeTelemetryConnector{}, false, nil
		}
		return models.RuntimeTelemetryConnector{}, true, fmt.Errorf("update runtime telemetry connector: %w", err)
	}
	return updated, true, nil
}

func (s *Store) ListRuntimeTelemetryEventsForTenant(ctx context.Context, tenantID string, query models.RuntimeTelemetryEventQuery) ([]models.RuntimeTelemetryEvent, error) {
	tenantID = strings.TrimSpace(tenantID)
	connectorID := strings.TrimSpace(query.ConnectorID)
	eventType := strings.ToLower(strings.TrimSpace(query.EventType))
	assetID := strings.TrimSpace(query.AssetID)
	findingID := strings.TrimSpace(query.FindingID)
	limit := query.Limit
	if limit <= 0 || limit > 2000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, connector_id, source_kind, source_ref, asset_id,
		       finding_id, event_type, severity, observed_at, payload_json,
		       evidence_refs_json, created_at
		FROM runtime_telemetry_events
		WHERE tenant_id = $1
		  AND ($2 = '' OR connector_id = $2)
		  AND ($3 = '' OR event_type = $3)
		  AND ($4 = '' OR asset_id = $4)
		  AND ($5 = '' OR finding_id = $5)
		ORDER BY observed_at DESC, id DESC
		LIMIT $6
	`, tenantID, connectorID, eventType, assetID, findingID, limit)
	if err != nil {
		return nil, fmt.Errorf("list runtime telemetry events: %w", err)
	}
	defer rows.Close()

	items := make([]models.RuntimeTelemetryEvent, 0, limit)
	for rows.Next() {
		item, err := scanRuntimeTelemetryEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan runtime telemetry event row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runtime telemetry event rows: %w", err)
	}
	return items, nil
}

func (s *Store) IngestRuntimeTelemetryEventForTenant(ctx context.Context, tenantID string, request models.IngestRuntimeTelemetryEventRequest) (models.RuntimeTelemetryEvent, error) {
	tenantID = strings.TrimSpace(tenantID)
	eventType := strings.ToLower(strings.TrimSpace(request.EventType))
	if eventType == "" {
		return models.RuntimeTelemetryEvent{}, fmt.Errorf("event_type is required")
	}

	connectorID := strings.TrimSpace(request.ConnectorID)

	observedAt := time.Now().UTC()
	if request.ObservedAt != nil {
		observedAt = request.ObservedAt.UTC()
	}

	item := models.RuntimeTelemetryEvent{
		ID:           nextRuntimeTelemetryEventID(),
		TenantID:     tenantID,
		ConnectorID:  connectorID,
		SourceKind:   strings.ToLower(strings.TrimSpace(request.SourceKind)),
		SourceRef:    strings.TrimSpace(request.SourceRef),
		AssetID:      strings.TrimSpace(request.AssetID),
		FindingID:    strings.TrimSpace(request.FindingID),
		EventType:    eventType,
		Severity:     normalizeRuntimeTelemetrySeverity(request.Severity),
		ObservedAt:   observedAt,
		Payload:      cloneRuntimeTelemetryMap(request.Payload),
		EvidenceRefs: sanitizeDesignStringList(request.EvidenceRefs),
		CreatedAt:    time.Now().UTC(),
	}
	if item.Severity == "" {
		item.Severity = "info"
	}

	payloadJSON, err := json.Marshal(item.Payload)
	if err != nil {
		return models.RuntimeTelemetryEvent{}, fmt.Errorf("marshal runtime telemetry event payload: %w", err)
	}
	evidenceJSON, err := json.Marshal(item.EvidenceRefs)
	if err != nil {
		return models.RuntimeTelemetryEvent{}, fmt.Errorf("marshal runtime telemetry event evidence refs: %w", err)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RuntimeTelemetryEvent{}, fmt.Errorf("begin runtime telemetry ingest tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if connectorID != "" {
		var connectorExists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1
				FROM runtime_telemetry_connectors
				WHERE tenant_id = $1
				  AND id = $2
			)
		`, tenantID, connectorID).Scan(&connectorExists); err != nil {
			return models.RuntimeTelemetryEvent{}, fmt.Errorf("validate runtime telemetry connector: %w", err)
		}
		if !connectorExists {
			return models.RuntimeTelemetryEvent{}, ErrTelemetryConnectorNotFound
		}
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO runtime_telemetry_events (
			id, tenant_id, connector_id, source_kind, source_ref, asset_id,
			finding_id, event_type, severity, observed_at, payload_json,
			evidence_refs_json, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13
		)
		RETURNING id, tenant_id, connector_id, source_kind, source_ref, asset_id,
		          finding_id, event_type, severity, observed_at, payload_json,
		          evidence_refs_json, created_at
	`, item.ID, item.TenantID, item.ConnectorID, item.SourceKind, item.SourceRef, item.AssetID,
		item.FindingID, item.EventType, item.Severity, item.ObservedAt, payloadJSON, evidenceJSON, item.CreatedAt)

	created, err := scanRuntimeTelemetryEvent(row)
	if err != nil {
		return models.RuntimeTelemetryEvent{}, fmt.Errorf("create runtime telemetry event: %w", err)
	}

	if strings.TrimSpace(created.AssetID) != "" {
		metadata := map[string]any{
			"runtime_event_id": created.ID,
			"event_type":       created.EventType,
			"severity":         created.Severity,
			"source_kind":      created.SourceKind,
			"source_ref":       created.SourceRef,
			"connector_id":     created.ConnectorID,
			"finding_id":       created.FindingID,
		}
		if len(created.EvidenceRefs) > 0 {
			metadata["evidence_refs"] = created.EvidenceRefs
		}
		if len(created.Payload) > 0 {
			metadata["payload"] = created.Payload
		}

		if err := publishPlatformEventTx(ctx, tx, models.PlatformEvent{
			TenantID:      tenantID,
			EventType:     "asset_context.runtime",
			SourceService: "control-plane",
			AggregateType: "asset",
			AggregateID:   strings.TrimSpace(created.AssetID),
			Payload: map[string]any{
				"asset_id":   strings.TrimSpace(created.AssetID),
				"asset_type": inferRuntimeAssetType(created.SourceKind),
				"event_kind": "runtime",
				"source":     strings.TrimSpace(created.SourceKind),
				"metadata":   metadata,
			},
			CreatedAt: created.CreatedAt,
		}); err != nil {
			return models.RuntimeTelemetryEvent{}, err
		}
	}

	if _, err := enrichFindingFromRuntimeEventTx(ctx, tx, created); err != nil {
		return models.RuntimeTelemetryEvent{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RuntimeTelemetryEvent{}, fmt.Errorf("commit runtime telemetry ingest tx: %w", err)
	}
	return created, nil
}

func scanRuntimeTelemetryConnector(row interface{ Scan(dest ...any) error }) (models.RuntimeTelemetryConnector, error) {
	var (
		item       models.RuntimeTelemetryConnector
		configJSON []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.Name,
		&item.ConnectorType,
		&item.Status,
		&configJSON,
		&item.LastSyncAt,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.RuntimeTelemetryConnector{}, err
	}
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &item.Config); err != nil {
			return models.RuntimeTelemetryConnector{}, fmt.Errorf("decode runtime telemetry connector config: %w", err)
		}
	}
	if item.Config == nil {
		item.Config = map[string]any{}
	}
	item.ConnectorType = normalizeRuntimeTelemetryConnectorType(item.ConnectorType)
	item.Status = normalizeRuntimeTelemetryConnectorStatus(item.Status)
	if item.Status == "" {
		item.Status = "draft"
	}
	return item, nil
}

func scanRuntimeTelemetryEvent(row interface{ Scan(dest ...any) error }) (models.RuntimeTelemetryEvent, error) {
	var (
		item         models.RuntimeTelemetryEvent
		payloadJSON  []byte
		evidenceJSON []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.ConnectorID,
		&item.SourceKind,
		&item.SourceRef,
		&item.AssetID,
		&item.FindingID,
		&item.EventType,
		&item.Severity,
		&item.ObservedAt,
		&payloadJSON,
		&evidenceJSON,
		&item.CreatedAt,
	)
	if err != nil {
		return models.RuntimeTelemetryEvent{}, err
	}
	if len(payloadJSON) > 0 {
		if err := json.Unmarshal(payloadJSON, &item.Payload); err != nil {
			return models.RuntimeTelemetryEvent{}, fmt.Errorf("decode runtime telemetry event payload: %w", err)
		}
	}
	if len(evidenceJSON) > 0 {
		if err := json.Unmarshal(evidenceJSON, &item.EvidenceRefs); err != nil {
			return models.RuntimeTelemetryEvent{}, fmt.Errorf("decode runtime telemetry event evidence refs: %w", err)
		}
	}
	if item.Payload == nil {
		item.Payload = map[string]any{}
	}
	item.EvidenceRefs = sanitizeDesignStringList(item.EvidenceRefs)
	item.Severity = normalizeRuntimeTelemetrySeverity(item.Severity)
	if item.Severity == "" {
		item.Severity = "info"
	}
	item.EventType = strings.ToLower(strings.TrimSpace(item.EventType))
	return item, nil
}

func normalizeRuntimeTelemetryConnectorType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "waf", "cdn", "api_gateway", "reverse_proxy", "cloud_audit", "service_mesh", "siem", "edr", "xdr", "custom":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeRuntimeTelemetryConnectorStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "draft", "active", "paused", "disabled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeRuntimeTelemetrySeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low", "info", "informational":
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "informational" {
			return "info"
		}
		return normalized
	default:
		return ""
	}
}

func cloneRuntimeTelemetryMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		out[trimmed] = value
	}
	return out
}

func inferRuntimeAssetType(sourceKind string) string {
	switch strings.ToLower(strings.TrimSpace(sourceKind)) {
	case "api_gateway":
		return "api"
	case "waf", "cdn", "reverse_proxy":
		return "domain"
	case "service_mesh", "edr", "xdr":
		return "host"
	case "cloud_audit":
		return "cloud_account"
	default:
		return "asset"
	}
}

func nextRuntimeTelemetryConnectorID() string {
	value := atomic.AddUint64(&telemetryConnectorSequence, 1)
	return fmt.Sprintf("telemetry-connector-%d-%06d", time.Now().UTC().Unix(), value)
}

func nextRuntimeTelemetryEventID() string {
	value := atomic.AddUint64(&telemetryEventSequence, 1)
	return fmt.Sprintf("telemetry-event-%d-%06d", time.Now().UTC().Unix(), value)
}
