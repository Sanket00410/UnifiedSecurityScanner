package models

type ExecutionMode string

const (
	ExecutionModePassive           ExecutionMode = "passive"
	ExecutionModeActiveValidation  ExecutionMode = "active_validation"
	ExecutionModeRestrictedExploit ExecutionMode = "restricted_exploit"
)

type WorkerCapability struct {
	AdapterID            string          `json:"adapter_id"`
	SupportedTargetKinds []string        `json:"supported_target_kinds"`
	SupportedModes       []ExecutionMode `json:"supported_modes"`
	Labels               []string        `json:"labels"`
	LinuxPreferred       bool            `json:"linux_preferred"`
}

type WorkerRegistrationRequest struct {
	WorkerID        string             `json:"worker_id"`
	WorkerVersion   string             `json:"worker_version"`
	OperatingSystem string             `json:"operating_system"`
	Hostname        string             `json:"hostname"`
	Capabilities    []WorkerCapability `json:"capabilities"`
}

type WorkerRegistrationResponse struct {
	Accepted                 bool   `json:"accepted"`
	LeaseID                  string `json:"lease_id"`
	HeartbeatIntervalSeconds int64  `json:"heartbeat_interval_seconds"`
}

type HeartbeatRequest struct {
	WorkerID      string            `json:"worker_id"`
	LeaseID       string            `json:"lease_id"`
	TimestampUnix int64             `json:"timestamp_unix"`
	Metrics       map[string]string `json:"metrics"`
}

type JobAssignment struct {
	JobID             string            `json:"job_id"`
	TenantID          string            `json:"tenant_id"`
	AdapterID         string            `json:"adapter_id"`
	TargetKind        string            `json:"target_kind"`
	Target            string            `json:"target"`
	ExecutionMode     ExecutionMode     `json:"execution_mode"`
	ApprovedModules   []string          `json:"approved_modules"`
	Labels            map[string]string `json:"labels"`
	MaxRuntimeSeconds int64             `json:"max_runtime_seconds"`
	EvidenceUploadURL string            `json:"evidence_upload_url"`
}

type HeartbeatResponse struct {
	Assignments []JobAssignment `json:"assignments"`
}

type TaskStatus string

const (
	TaskStatusQueued    TaskStatus = "queued"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCanceled  TaskStatus = "canceled"
)

type TaskContext struct {
	TaskID     string
	ScanJobID  string
	TenantID   string
	AdapterID  string
	TargetKind string
	Target     string
}
