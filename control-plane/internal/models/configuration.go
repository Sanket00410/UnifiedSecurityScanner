package models

import "time"

type TenantConfigEntry struct {
	TenantID  string         `json:"tenant_id,omitempty"`
	Key       string         `json:"key"`
	Value     map[string]any `json:"value"`
	UpdatedBy string         `json:"updated_by,omitempty"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type UpsertTenantConfigRequest struct {
	Value map[string]any `json:"value"`
}
