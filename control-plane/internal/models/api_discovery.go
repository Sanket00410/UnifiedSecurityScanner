package models

import (
	"encoding/json"
	"time"
)

type APIAsset struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	BaseURL       string    `json:"base_url,omitempty"`
	Source        string    `json:"source"`
	SpecVersion   string    `json:"spec_version,omitempty"`
	SpecHash      string    `json:"spec_hash,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	EndpointCount int64     `json:"endpoint_count,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type APIEndpoint struct {
	ID           string    `json:"id"`
	APIAssetID   string    `json:"api_asset_id"`
	TenantID     string    `json:"tenant_id"`
	Path         string    `json:"path"`
	Method       string    `json:"method"`
	OperationID  string    `json:"operation_id,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	AuthRequired bool      `json:"auth_required"`
	CreatedAt    time.Time `json:"created_at"`
}

type ImportOpenAPIRequest struct {
	Name    string          `json:"name"`
	BaseURL string          `json:"base_url"`
	Source  string          `json:"source"`
	Spec    json.RawMessage `json:"spec"`
}

type ImportGraphQLSchemaRequest struct {
	Name         string `json:"name"`
	BaseURL      string `json:"base_url"`
	Source       string `json:"source"`
	EndpointPath string `json:"endpoint_path"`
	Schema       string `json:"schema"`
	AuthRequired *bool  `json:"auth_required"`
}

type ImportedAPIAsset struct {
	Asset         APIAsset `json:"asset"`
	EndpointCount int64    `json:"endpoint_count"`
}
