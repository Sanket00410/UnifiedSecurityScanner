package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListTenantConfigForTenant(ctx context.Context, tenantID string, prefix string, limit int) ([]models.TenantConfigEntry, error) {
	tenantID = strings.TrimSpace(tenantID)
	prefix = normalizeTenantConfigKey(prefix)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id, config_key, config_json, updated_by, updated_at
		FROM tenant_config
		WHERE tenant_id = $1
		  AND ($2 = '' OR config_key LIKE $2 || '%')
		ORDER BY config_key ASC
		LIMIT $3
	`, tenantID, prefix, limit)
	if err != nil {
		return nil, fmt.Errorf("list tenant config: %w", err)
	}
	defer rows.Close()

	out := make([]models.TenantConfigEntry, 0, limit)
	for rows.Next() {
		entry, err := scanTenantConfigEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tenant config row: %w", err)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant config rows: %w", err)
	}

	return out, nil
}

func (s *Store) GetTenantConfigEntryForTenant(ctx context.Context, tenantID string, key string) (models.TenantConfigEntry, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	key = normalizeTenantConfigKey(key)
	if key == "" {
		return models.TenantConfigEntry{}, false, nil
	}

	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, config_key, config_json, updated_by, updated_at
		FROM tenant_config
		WHERE tenant_id = $1
		  AND config_key = $2
	`, tenantID, key)

	entry, err := scanTenantConfigEntry(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.TenantConfigEntry{}, false, nil
		}
		return models.TenantConfigEntry{}, false, fmt.Errorf("get tenant config entry: %w", err)
	}

	return entry, true, nil
}

func (s *Store) UpsertTenantConfigEntryForTenant(ctx context.Context, tenantID string, key string, actor string, request models.UpsertTenantConfigRequest) (models.TenantConfigEntry, error) {
	tenantID = strings.TrimSpace(tenantID)
	key = normalizeTenantConfigKey(key)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	if key == "" {
		return models.TenantConfigEntry{}, fmt.Errorf("config key is required")
	}

	value := request.Value
	if value == nil {
		value = map[string]any{}
	}
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return models.TenantConfigEntry{}, fmt.Errorf("marshal tenant config value: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.pool.Exec(ctx, `
		INSERT INTO tenant_config (
			tenant_id, config_key, config_json, updated_by, updated_at
		) VALUES (
			$1, $2, $3, $4, $5
		)
		ON CONFLICT (tenant_id, config_key) DO UPDATE SET
			config_json = EXCLUDED.config_json,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
	`, tenantID, key, valueJSON, actor, now)
	if err != nil {
		return models.TenantConfigEntry{}, fmt.Errorf("upsert tenant config entry: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "tenant_config.upserted",
		SourceService: "control-plane",
		AggregateType: "tenant_config",
		AggregateID:   key,
		Payload: map[string]any{
			"key":        key,
			"updated_by": actor,
		},
		CreatedAt: now,
	})

	return models.TenantConfigEntry{
		TenantID:  tenantID,
		Key:       key,
		Value:     value,
		UpdatedBy: actor,
		UpdatedAt: now,
	}, nil
}

func (s *Store) DeleteTenantConfigEntryForTenant(ctx context.Context, tenantID string, key string, actor string) (bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	key = normalizeTenantConfigKey(key)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	if key == "" {
		return false, nil
	}

	result, err := s.pool.Exec(ctx, `
		DELETE FROM tenant_config
		WHERE tenant_id = $1
		  AND config_key = $2
	`, tenantID, key)
	if err != nil {
		return false, fmt.Errorf("delete tenant config entry: %w", err)
	}

	if result.RowsAffected() > 0 {
		_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
			TenantID:      tenantID,
			EventType:     "tenant_config.deleted",
			SourceService: "control-plane",
			AggregateType: "tenant_config",
			AggregateID:   key,
			Payload: map[string]any{
				"key":        key,
				"deleted_by": actor,
			},
			CreatedAt: time.Now().UTC(),
		})
	}

	return result.RowsAffected() > 0, nil
}

func scanTenantConfigEntry(row interface{ Scan(dest ...any) error }) (models.TenantConfigEntry, error) {
	var (
		entry     models.TenantConfigEntry
		valueJSON []byte
	)

	err := row.Scan(&entry.TenantID, &entry.Key, &valueJSON, &entry.UpdatedBy, &entry.UpdatedAt)
	if err != nil {
		return models.TenantConfigEntry{}, err
	}

	if len(valueJSON) > 0 {
		if err := json.Unmarshal(valueJSON, &entry.Value); err != nil {
			return models.TenantConfigEntry{}, fmt.Errorf("decode tenant config value: %w", err)
		}
	}
	if entry.Value == nil {
		entry.Value = map[string]any{}
	}

	return entry, nil
}

func normalizeTenantConfigKey(value string) string {
	key := strings.ToLower(strings.TrimSpace(value))
	key = strings.Trim(key, ".")
	key = strings.ReplaceAll(key, " ", "_")
	return key
}
