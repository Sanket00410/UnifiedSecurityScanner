package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"unifiedsecurityscanner/platform-services/internal/models"
)

func (s *Store) CreateConnector(ctx context.Context, tenantID string, actor string, request models.CreateConnectorRequest) (models.Connector, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	name := strings.TrimSpace(request.Name)
	if name == "" {
		return models.Connector{}, errors.New("connector name is required")
	}
	connectorKind := normalizeConnectorKind(request.ConnectorKind)
	if !isSupportedConnectorKind(connectorKind) {
		return models.Connector{}, fmt.Errorf("unsupported connector kind %q", connectorKind)
	}

	retryMaxAttempts := clampInt(request.RetryMaxAttempts, 1, 10, defaultRetryAttempts)
	retryBaseDelaySeconds := clampInt(request.RetryBaseDelaySeconds, 1, 3600, defaultRetryBaseSecs)
	retryMaxDelaySeconds := clampInt(request.RetryMaxDelaySeconds, retryBaseDelaySeconds, 86400, defaultRetryMaxSecs)

	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}

	now := time.Now().UTC()
	connector := models.Connector{
		ID:                    nextID("connector"),
		TenantID:              normalizedTenantID,
		Name:                  name,
		ConnectorKind:         connectorKind,
		EndpointURL:           strings.TrimSpace(request.EndpointURL),
		AuthType:              normalizeAuthType(request.AuthType),
		AuthSecretRef:         strings.TrimSpace(request.AuthSecretRef),
		DefaultHeaders:        cloneStringMap(request.DefaultHeaders),
		Metadata:              cloneAnyMap(request.Metadata),
		Enabled:               enabled,
		RetryMaxAttempts:      retryMaxAttempts,
		RetryBaseDelaySeconds: retryBaseDelaySeconds,
		RetryMaxDelaySeconds:  retryMaxDelaySeconds,
		CreatedBy:             normalizeActor(actor),
		UpdatedBy:             normalizeActor(actor),
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO ps_connectors (
			id, tenant_id, name, connector_kind, endpoint_url, auth_type, auth_secret_ref,
			default_headers_json, metadata_json, enabled,
			retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds,
			created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8::jsonb, $9::jsonb, $10,
			$11, $12, $13,
			$14, $15, $16, $17
		)
	`,
		connector.ID,
		connector.TenantID,
		connector.Name,
		connector.ConnectorKind,
		connector.EndpointURL,
		connector.AuthType,
		connector.AuthSecretRef,
		marshalStringMap(connector.DefaultHeaders),
		marshalAnyMap(connector.Metadata),
		connector.Enabled,
		connector.RetryMaxAttempts,
		connector.RetryBaseDelaySeconds,
		connector.RetryMaxDelaySeconds,
		connector.CreatedBy,
		connector.UpdatedBy,
		connector.CreatedAt,
		connector.UpdatedAt,
	)
	if err != nil {
		return models.Connector{}, fmt.Errorf("insert connector: %w", err)
	}

	return connector, nil
}

func (s *Store) ListConnectors(ctx context.Context, tenantID string, kind string, limit int) ([]models.Connector, error) {
	normalizedTenantID := s.ResolveTenantID(tenantID)
	normalizedKind := normalizeConnectorKind(kind)
	normalizedLimit := normalizeLimit(limit, defaultListLimit)

	query := `
		SELECT
			id, tenant_id, name, connector_kind, endpoint_url, auth_type, auth_secret_ref,
			default_headers_json, metadata_json, enabled,
			retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds,
			created_by, updated_by, created_at, updated_at
		FROM ps_connectors
		WHERE tenant_id = $1
	`
	args := []any{normalizedTenantID}
	if normalizedKind != "" {
		query += " AND connector_kind = $2 ORDER BY updated_at DESC LIMIT $3"
		args = append(args, normalizedKind, normalizedLimit)
	} else {
		query += " ORDER BY updated_at DESC LIMIT $2"
		args = append(args, normalizedLimit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list connectors: %w", err)
	}
	defer rows.Close()

	results := make([]models.Connector, 0, normalizedLimit)
	for rows.Next() {
		item, scanErr := scanConnector(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connectors: %w", err)
	}
	return results, nil
}

func (s *Store) GetConnector(ctx context.Context, tenantID string, connectorID string) (models.Connector, bool, error) {
	return s.loadConnector(ctx, s.ResolveTenantID(tenantID), strings.TrimSpace(connectorID))
}

func (s *Store) UpdateConnector(ctx context.Context, tenantID string, connectorID string, actor string, request models.UpdateConnectorRequest) (models.Connector, bool, error) {
	existing, found, err := s.loadConnector(ctx, s.ResolveTenantID(tenantID), strings.TrimSpace(connectorID))
	if err != nil {
		return models.Connector{}, false, err
	}
	if !found {
		return models.Connector{}, false, nil
	}

	if name := strings.TrimSpace(request.Name); name != "" {
		existing.Name = name
	}
	if endpointURL := strings.TrimSpace(request.EndpointURL); endpointURL != "" {
		existing.EndpointURL = endpointURL
	}
	if authType := strings.TrimSpace(request.AuthType); authType != "" {
		existing.AuthType = normalizeAuthType(authType)
	}
	if secretRef := strings.TrimSpace(request.AuthSecretRef); secretRef != "" {
		existing.AuthSecretRef = secretRef
	}
	if request.DefaultHeaders != nil {
		existing.DefaultHeaders = cloneStringMap(request.DefaultHeaders)
	}
	if request.Metadata != nil {
		existing.Metadata = cloneAnyMap(request.Metadata)
	}
	if request.Enabled != nil {
		existing.Enabled = *request.Enabled
	}
	if request.RetryMaxAttempts > 0 {
		existing.RetryMaxAttempts = clampInt(request.RetryMaxAttempts, 1, 10, existing.RetryMaxAttempts)
	}
	if request.RetryBaseDelaySeconds > 0 {
		existing.RetryBaseDelaySeconds = clampInt(request.RetryBaseDelaySeconds, 1, 3600, existing.RetryBaseDelaySeconds)
	}
	if request.RetryMaxDelaySeconds > 0 {
		existing.RetryMaxDelaySeconds = clampInt(request.RetryMaxDelaySeconds, existing.RetryBaseDelaySeconds, 86400, existing.RetryMaxDelaySeconds)
	}
	if existing.RetryMaxDelaySeconds < existing.RetryBaseDelaySeconds {
		existing.RetryMaxDelaySeconds = existing.RetryBaseDelaySeconds
	}

	existing.UpdatedBy = normalizeActor(actor)
	existing.UpdatedAt = time.Now().UTC()

	row := s.pool.QueryRow(ctx, `
		UPDATE ps_connectors
		SET
			name = $3,
			endpoint_url = $4,
			auth_type = $5,
			auth_secret_ref = $6,
			default_headers_json = $7::jsonb,
			metadata_json = $8::jsonb,
			enabled = $9,
			retry_max_attempts = $10,
			retry_base_delay_seconds = $11,
			retry_max_delay_seconds = $12,
			updated_by = $13,
			updated_at = $14
		WHERE tenant_id = $1 AND id = $2
		RETURNING
			id, tenant_id, name, connector_kind, endpoint_url, auth_type, auth_secret_ref,
			default_headers_json, metadata_json, enabled,
			retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds,
			created_by, updated_by, created_at, updated_at
	`,
		existing.TenantID,
		existing.ID,
		existing.Name,
		existing.EndpointURL,
		existing.AuthType,
		existing.AuthSecretRef,
		marshalStringMap(existing.DefaultHeaders),
		marshalAnyMap(existing.Metadata),
		existing.Enabled,
		existing.RetryMaxAttempts,
		existing.RetryBaseDelaySeconds,
		existing.RetryMaxDelaySeconds,
		existing.UpdatedBy,
		existing.UpdatedAt,
	)
	updated, scanErr := scanConnector(row)
	if scanErr != nil {
		return models.Connector{}, false, scanErr
	}
	return updated, true, nil
}

func (s *Store) loadConnector(ctx context.Context, tenantID string, connectorID string) (models.Connector, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT
			id, tenant_id, name, connector_kind, endpoint_url, auth_type, auth_secret_ref,
			default_headers_json, metadata_json, enabled,
			retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds,
			created_by, updated_by, created_at, updated_at
		FROM ps_connectors
		WHERE tenant_id = $1 AND id = $2
	`,
		tenantID,
		connectorID,
	)
	connector, err := scanConnector(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Connector{}, false, nil
		}
		return models.Connector{}, false, err
	}
	return connector, true, nil
}

func (s *Store) loadConnectorTx(ctx context.Context, tx pgx.Tx, tenantID string, connectorID string) (models.Connector, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT
			id, tenant_id, name, connector_kind, endpoint_url, auth_type, auth_secret_ref,
			default_headers_json, metadata_json, enabled,
			retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds,
			created_by, updated_by, created_at, updated_at
		FROM ps_connectors
		WHERE tenant_id = $1 AND id = $2
	`,
		tenantID,
		connectorID,
	)
	connector, err := scanConnector(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Connector{}, false, nil
		}
		return models.Connector{}, false, err
	}
	return connector, true, nil
}
