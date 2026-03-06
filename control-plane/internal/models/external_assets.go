package models

import "time"

type ExternalAsset struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	AssetType   string         `json:"asset_type"`
	Value       string         `json:"value"`
	Source      string         `json:"source"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	FirstSeenAt time.Time      `json:"first_seen_at"`
	LastSeenAt  time.Time      `json:"last_seen_at"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type UpsertExternalAssetRequest struct {
	AssetType string         `json:"asset_type"`
	Value     string         `json:"value"`
	Source    string         `json:"source"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type SyncExternalAssetsRequest struct {
	Source string                       `json:"source"`
	Assets []UpsertExternalAssetRequest `json:"assets"`
}

type SyncExternalAssetsResult struct {
	ImportedCount int             `json:"imported_count"`
	Items         []ExternalAsset `json:"items"`
}
