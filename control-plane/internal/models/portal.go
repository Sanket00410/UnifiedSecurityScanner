package models

import "time"

type AssetSummary struct {
	AssetID       string    `json:"asset_id"`
	AssetType     string    `json:"asset_type"`
	LastScannedAt time.Time `json:"last_scanned_at"`
	ScanCount     int64     `json:"scan_count"`
	FindingCount  int64     `json:"finding_count"`
}

type Policy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`
	Mode      string    `json:"mode"`
	Enabled   bool      `json:"enabled"`
	Rules     []string  `json:"rules"`
	UpdatedBy string    `json:"updated_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CreatePolicyRequest struct {
	Name      string   `json:"name"`
	Scope     string   `json:"scope"`
	Mode      string   `json:"mode"`
	Enabled   bool     `json:"enabled"`
	Rules     []string `json:"rules"`
	UpdatedBy string   `json:"updated_by"`
}

type RemediationAction struct {
	ID        string     `json:"id"`
	FindingID string     `json:"finding_id"`
	Title     string     `json:"title"`
	Status    string     `json:"status"`
	Owner     string     `json:"owner"`
	DueAt     *time.Time `json:"due_at,omitempty"`
	Notes     string     `json:"notes,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type CreateRemediationRequest struct {
	FindingID string     `json:"finding_id"`
	Title     string     `json:"title"`
	Status    string     `json:"status"`
	Owner     string     `json:"owner"`
	DueAt     *time.Time `json:"due_at,omitempty"`
	Notes     string     `json:"notes,omitempty"`
}
