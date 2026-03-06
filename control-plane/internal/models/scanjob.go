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
	TenantID    string            `json:"tenant_id"`
	TargetKind  string            `json:"target_kind"`
	Target      string            `json:"target"`
	Profile     string            `json:"profile"`
	RequestedBy string            `json:"requested_by"`
	Tools       []string          `json:"tools"`
	TaskLabels  map[string]string `json:"task_labels,omitempty"`
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

type ScanPreset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	TargetKind  string   `json:"target_kind"`
	Profile     string   `json:"profile"`
	Tools       []string `json:"tools"`
}

type ScanTarget struct {
	ID         string         `json:"id"`
	TenantID   string         `json:"tenant_id"`
	Name       string         `json:"name"`
	TargetKind string         `json:"target_kind"`
	Target     string         `json:"target"`
	Profile    string         `json:"profile"`
	Tools      []string       `json:"tools"`
	Labels     map[string]any `json:"labels,omitempty"`
	CreatedBy  string         `json:"created_by"`
	LastRunAt  *time.Time     `json:"last_run_at,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

type CreateScanTargetRequest struct {
	Name       string         `json:"name"`
	TargetKind string         `json:"target_kind"`
	Target     string         `json:"target"`
	Profile    string         `json:"profile"`
	Tools      []string       `json:"tools"`
	Labels     map[string]any `json:"labels,omitempty"`
}

type UpdateScanTargetRequest struct {
	Name       string         `json:"name"`
	TargetKind string         `json:"target_kind"`
	Target     string         `json:"target"`
	Profile    string         `json:"profile"`
	Tools      []string       `json:"tools"`
	Labels     map[string]any `json:"labels,omitempty"`
}

type RunScanTargetRequest struct {
	Profile string   `json:"profile"`
	Tools   []string `json:"tools"`
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
