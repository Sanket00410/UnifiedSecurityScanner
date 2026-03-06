package models

import "time"

type PlatformEvent struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id,omitempty"`
	EventType     string         `json:"event_type"`
	SourceService string         `json:"source_service,omitempty"`
	AggregateType string         `json:"aggregate_type,omitempty"`
	AggregateID   string         `json:"aggregate_id,omitempty"`
	Payload       map[string]any `json:"payload,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

type TenantLimits struct {
	TenantID             string    `json:"tenant_id"`
	MaxTotalScanJobs     int64     `json:"max_total_scan_jobs"`
	MaxActiveScanJobs    int64     `json:"max_active_scan_jobs"`
	MaxScanJobsPerMinute int64     `json:"max_scan_jobs_per_minute"`
	MaxScanTargets       int64     `json:"max_scan_targets"`
	MaxIngestionSources  int64     `json:"max_ingestion_sources"`
	UpdatedBy            string    `json:"updated_by,omitempty"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type UpdateTenantLimitsRequest struct {
	MaxTotalScanJobs     *int64 `json:"max_total_scan_jobs"`
	MaxActiveScanJobs    *int64 `json:"max_active_scan_jobs"`
	MaxScanJobsPerMinute *int64 `json:"max_scan_jobs_per_minute"`
	MaxScanTargets       *int64 `json:"max_scan_targets"`
	MaxIngestionSources  *int64 `json:"max_ingestion_sources"`
}

type TenantUsage struct {
	TotalScanJobs    int64 `json:"total_scan_jobs"`
	ActiveScanJobs   int64 `json:"active_scan_jobs"`
	ScanTargets      int64 `json:"scan_targets"`
	IngestionSources int64 `json:"ingestion_sources"`
}

type TenantOperationsSnapshot struct {
	TenantID string       `json:"tenant_id"`
	Limits   TenantLimits `json:"limits"`
	Usage    TenantUsage  `json:"usage"`
}

type OperationalMetrics struct {
	WorkersTotal        int64 `json:"workers_total"`
	WorkersHealthy      int64 `json:"workers_healthy"`
	ScanJobsTotal       int64 `json:"scan_jobs_total"`
	ScanJobsQueued      int64 `json:"scan_jobs_queued"`
	ScanJobsRunning     int64 `json:"scan_jobs_running"`
	ScanJobsCompleted   int64 `json:"scan_jobs_completed"`
	ScanJobsFailed      int64 `json:"scan_jobs_failed"`
	ScanTargetsTotal    int64 `json:"scan_targets_total"`
	IngestionSources    int64 `json:"ingestion_sources_total"`
	IngestionEvents     int64 `json:"ingestion_events_total"`
	PlatformEventsTotal int64 `json:"platform_events_total"`
}
