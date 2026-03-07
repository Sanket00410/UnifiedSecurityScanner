package models

import "time"

type RuntimeFindingEnrichment struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id,omitempty"`
	FindingID        string    `json:"finding_id"`
	TelemetryEventID string    `json:"telemetry_event_id"`
	EventType        string    `json:"event_type"`
	Severity         string    `json:"severity,omitempty"`
	ConfidenceBefore string    `json:"confidence_before,omitempty"`
	ConfidenceAfter  string    `json:"confidence_after,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

type RuntimeEnrichmentBackfillResult struct {
	ProcessedEvents  int64 `json:"processed_events"`
	EnrichedFindings int64 `json:"enriched_findings"`
	SkippedEvents    int64 `json:"skipped_events"`
}
