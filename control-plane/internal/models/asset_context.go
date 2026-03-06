package models

import "time"

type AssetContextEvent struct {
	ID        string         `json:"id"`
	TenantID  string         `json:"tenant_id"`
	AssetID   string         `json:"asset_id"`
	AssetType string         `json:"asset_type"`
	EventKind string         `json:"event_kind"`
	Source    string         `json:"source"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type CreateAssetContextEventRequest struct {
	AssetID   string         `json:"asset_id"`
	AssetType string         `json:"asset_type"`
	EventKind string         `json:"event_kind"`
	Source    string         `json:"source"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}
