package models

import "time"

type IngestionSource struct {
	ID                string         `json:"id"`
	TenantID          string         `json:"tenant_id"`
	Name              string         `json:"name"`
	Provider          string         `json:"provider"`
	Enabled           bool           `json:"enabled"`
	SignatureRequired bool           `json:"signature_required"`
	TargetKind        string         `json:"target_kind"`
	Target            string         `json:"target"`
	Profile           string         `json:"profile"`
	Tools             []string       `json:"tools"`
	Labels            map[string]any `json:"labels,omitempty"`
	CreatedBy         string         `json:"created_by"`
	UpdatedBy         string         `json:"updated_by"`
	LastEventAt       *time.Time     `json:"last_event_at,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

type CreateIngestionSourceRequest struct {
	Name              string         `json:"name"`
	Provider          string         `json:"provider"`
	Enabled           *bool          `json:"enabled"`
	SignatureRequired *bool          `json:"signature_required"`
	WebhookSecret     string         `json:"webhook_secret,omitempty"`
	TargetKind        string         `json:"target_kind"`
	Target            string         `json:"target"`
	Profile           string         `json:"profile"`
	Tools             []string       `json:"tools"`
	Labels            map[string]any `json:"labels,omitempty"`
}

type UpdateIngestionSourceRequest struct {
	Name              string         `json:"name"`
	Provider          string         `json:"provider"`
	Enabled           *bool          `json:"enabled"`
	SignatureRequired *bool          `json:"signature_required"`
	WebhookSecret     string         `json:"webhook_secret,omitempty"`
	TargetKind        string         `json:"target_kind"`
	Target            string         `json:"target"`
	Profile           string         `json:"profile"`
	Tools             []string       `json:"tools"`
	Labels            map[string]any `json:"labels,omitempty"`
}

type CreatedIngestionSource struct {
	Source      IngestionSource `json:"source"`
	IngestToken string          `json:"ingest_token"`
}

type RotateIngestionSourceTokenResponse struct {
	Source      IngestionSource `json:"source"`
	IngestToken string          `json:"ingest_token"`
}

type IngestionEvent struct {
	ID               string         `json:"id"`
	TenantID         string         `json:"tenant_id"`
	SourceID         string         `json:"source_id"`
	EventType        string         `json:"event_type"`
	ExternalID       string         `json:"external_id,omitempty"`
	Status           string         `json:"status"`
	ErrorMessage     string         `json:"error_message,omitempty"`
	CreatedScanJobID string         `json:"created_scan_job_id,omitempty"`
	PolicyID         string         `json:"policy_id,omitempty"`
	PolicyRuleHits   []string       `json:"policy_rule_hits,omitempty"`
	Payload          map[string]any `json:"payload,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type IngestionWebhookRequest struct {
	EventType   string            `json:"event_type"`
	ExternalID  string            `json:"external_id"`
	TargetKind  string            `json:"target_kind"`
	Target      string            `json:"target"`
	Profile     string            `json:"profile"`
	Tools       []string          `json:"tools"`
	RequestedBy string            `json:"requested_by"`
	Headers     map[string]string `json:"headers,omitempty"`
	Payload     map[string]any    `json:"payload,omitempty"`
	Labels      map[string]any    `json:"labels,omitempty"`
	Metadata    map[string]any    `json:"metadata,omitempty"`
}

type IngestionWebhookResponse struct {
	Event     IngestionEvent `json:"event"`
	Job       *ScanJob       `json:"job,omitempty"`
	Duplicate bool           `json:"duplicate"`
}
