package models

import "time"

type ScanJobStatus string

const (
	ScanJobStatusQueued    ScanJobStatus = "queued"
	ScanJobStatusRunning   ScanJobStatus = "running"
	ScanJobStatusCompleted ScanJobStatus = "completed"
	ScanJobStatusFailed    ScanJobStatus = "failed"
)

type CreateScanJobRequest struct {
	TenantID    string   `json:"tenant_id"`
	TargetKind  string   `json:"target_kind"`
	Target      string   `json:"target"`
	Profile     string   `json:"profile"`
	RequestedBy string   `json:"requested_by"`
	Tools       []string `json:"tools"`
}

type ScanJob struct {
	ID           string        `json:"id"`
	TenantID     string        `json:"tenant_id"`
	TargetKind   string        `json:"target_kind"`
	Target       string        `json:"target"`
	Profile      string        `json:"profile"`
	RequestedBy  string        `json:"requested_by"`
	Tools        []string      `json:"tools"`
	ApprovalMode string        `json:"approval_mode"`
	Status       ScanJobStatus `json:"status"`
	RequestedAt  time.Time     `json:"requested_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ServiceMetadata struct {
	Name                      string `json:"name"`
	Version                   string `json:"version"`
	SchedulerIntervalSeconds  int64  `json:"scheduler_interval_seconds"`
	WorkerHeartbeatTTLSeconds int64  `json:"worker_heartbeat_ttl_seconds"`
}
