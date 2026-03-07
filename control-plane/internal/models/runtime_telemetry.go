package models

import "time"

type RuntimeTelemetryConnector struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id,omitempty"`
	Name          string         `json:"name"`
	ConnectorType string         `json:"connector_type"`
	Status        string         `json:"status"`
	Config        map[string]any `json:"config,omitempty"`
	LastSyncAt    *time.Time     `json:"last_sync_at,omitempty"`
	CreatedBy     string         `json:"created_by,omitempty"`
	UpdatedBy     string         `json:"updated_by,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type CreateRuntimeTelemetryConnectorRequest struct {
	Name          string         `json:"name"`
	ConnectorType string         `json:"connector_type"`
	Status        string         `json:"status"`
	Config        map[string]any `json:"config"`
}

type UpdateRuntimeTelemetryConnectorRequest struct {
	Name          string         `json:"name"`
	ConnectorType string         `json:"connector_type"`
	Status        string         `json:"status"`
	Config        map[string]any `json:"config"`
	LastSyncAt    *time.Time     `json:"last_sync_at,omitempty"`
}

type RuntimeTelemetryEvent struct {
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id,omitempty"`
	ConnectorID  string         `json:"connector_id,omitempty"`
	SourceKind   string         `json:"source_kind,omitempty"`
	SourceRef    string         `json:"source_ref,omitempty"`
	AssetID      string         `json:"asset_id,omitempty"`
	FindingID    string         `json:"finding_id,omitempty"`
	EventType    string         `json:"event_type"`
	Severity     string         `json:"severity,omitempty"`
	ObservedAt   time.Time      `json:"observed_at"`
	Payload      map[string]any `json:"payload,omitempty"`
	EvidenceRefs []string       `json:"evidence_refs,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

type RuntimeTelemetryEventQuery struct {
	ConnectorID string `json:"connector_id,omitempty"`
	EventType   string `json:"event_type,omitempty"`
	AssetID     string `json:"asset_id,omitempty"`
	FindingID   string `json:"finding_id,omitempty"`
	Limit       int    `json:"limit,omitempty"`
}

type IngestRuntimeTelemetryEventRequest struct {
	ConnectorID  string         `json:"connector_id"`
	SourceKind   string         `json:"source_kind"`
	SourceRef    string         `json:"source_ref"`
	AssetID      string         `json:"asset_id"`
	FindingID    string         `json:"finding_id"`
	EventType    string         `json:"event_type"`
	Severity     string         `json:"severity"`
	ObservedAt   *time.Time     `json:"observed_at,omitempty"`
	Payload      map[string]any `json:"payload"`
	EvidenceRefs []string       `json:"evidence_refs"`
}
