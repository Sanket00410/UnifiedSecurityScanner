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
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id,omitempty"`
	VersionNumber int64     `json:"version_number"`
	Name          string    `json:"name"`
	Scope         string    `json:"scope"`
	Mode          string    `json:"mode"`
	Enabled       bool      `json:"enabled"`
	Rules         []string  `json:"rules"`
	UpdatedBy     string    `json:"updated_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type CreatePolicyRequest struct {
	Name      string   `json:"name"`
	Scope     string   `json:"scope"`
	Mode      string   `json:"mode"`
	Enabled   bool     `json:"enabled"`
	Rules     []string `json:"rules"`
	UpdatedBy string   `json:"updated_by"`
	Global    bool     `json:"global"`
}

type UpdatePolicyRequest struct {
	Name      string   `json:"name"`
	Scope     string   `json:"scope"`
	Mode      string   `json:"mode"`
	Enabled   bool     `json:"enabled"`
	Rules     []string `json:"rules"`
	UpdatedBy string   `json:"updated_by"`
}

type PolicyVersion struct {
	ID            string    `json:"id"`
	PolicyID      string    `json:"policy_id"`
	VersionNumber int64     `json:"version_number"`
	ChangeType    string    `json:"change_type"`
	Snapshot      Policy    `json:"snapshot"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
}

type PolicyRollbackRequest struct {
	VersionNumber int64 `json:"version_number"`
}

type PolicyApproval struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	ScanJobID   string     `json:"scan_job_id"`
	TaskID      string     `json:"task_id"`
	PolicyID    string     `json:"policy_id,omitempty"`
	Action      string     `json:"action"`
	Status      string     `json:"status"`
	RequestedBy string     `json:"requested_by"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
}

type PolicyApprovalDecisionRequest struct {
	Reason string `json:"reason"`
}

type RemediationAction struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id,omitempty"`
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
