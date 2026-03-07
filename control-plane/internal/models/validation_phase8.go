package models

import "time"

type ValidationEngagement struct {
	ID                     string     `json:"id"`
	TenantID               string     `json:"tenant_id,omitempty"`
	Name                   string     `json:"name"`
	Status                 string     `json:"status"`
	TargetKind             string     `json:"target_kind,omitempty"`
	Target                 string     `json:"target,omitempty"`
	PolicyPackRef          string     `json:"policy_pack_ref,omitempty"`
	AllowedTools           []string   `json:"allowed_tools,omitempty"`
	RequiresManualApproval bool       `json:"requires_manual_approval"`
	Notes                  string     `json:"notes,omitempty"`
	RequestedBy            string     `json:"requested_by,omitempty"`
	ApprovedBy             string     `json:"approved_by,omitempty"`
	ApprovedAt             *time.Time `json:"approved_at,omitempty"`
	ActivatedBy            string     `json:"activated_by,omitempty"`
	ActivatedAt            *time.Time `json:"activated_at,omitempty"`
	ClosedBy               string     `json:"closed_by,omitempty"`
	ClosedAt               *time.Time `json:"closed_at,omitempty"`
	StartAt                *time.Time `json:"start_at,omitempty"`
	EndAt                  *time.Time `json:"end_at,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

type CreateValidationEngagementRequest struct {
	Name                   string     `json:"name"`
	TargetKind             string     `json:"target_kind"`
	Target                 string     `json:"target"`
	PolicyPackRef          string     `json:"policy_pack_ref"`
	AllowedTools           []string   `json:"allowed_tools"`
	RequiresManualApproval *bool      `json:"requires_manual_approval"`
	Notes                  string     `json:"notes"`
	StartAt                *time.Time `json:"start_at,omitempty"`
	EndAt                  *time.Time `json:"end_at,omitempty"`
}

type UpdateValidationEngagementRequest struct {
	Name                   string     `json:"name"`
	TargetKind             string     `json:"target_kind"`
	Target                 string     `json:"target"`
	PolicyPackRef          string     `json:"policy_pack_ref"`
	AllowedTools           []string   `json:"allowed_tools"`
	RequiresManualApproval *bool      `json:"requires_manual_approval"`
	Notes                  string     `json:"notes"`
	StartAt                *time.Time `json:"start_at,omitempty"`
	EndAt                  *time.Time `json:"end_at,omitempty"`
}

type ValidationEngagementDecisionRequest struct {
	Reason string `json:"reason"`
}

type ValidationAttackTrace struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id,omitempty"`
	EngagementID   string         `json:"engagement_id"`
	ScanJobID      string         `json:"scan_job_id,omitempty"`
	TaskID         string         `json:"task_id,omitempty"`
	AdapterID      string         `json:"adapter_id,omitempty"`
	TargetKind     string         `json:"target_kind,omitempty"`
	Target         string         `json:"target,omitempty"`
	Title          string         `json:"title"`
	Summary        string         `json:"summary,omitempty"`
	Severity       string         `json:"severity,omitempty"`
	EvidenceRefs   []string       `json:"evidence_refs,omitempty"`
	Artifacts      map[string]any `json:"artifacts,omitempty"`
	ReplayManifest map[string]any `json:"replay_manifest,omitempty"`
	CreatedBy      string         `json:"created_by,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type CreateValidationAttackTraceRequest struct {
	EngagementID   string         `json:"engagement_id"`
	ScanJobID      string         `json:"scan_job_id"`
	TaskID         string         `json:"task_id"`
	AdapterID      string         `json:"adapter_id"`
	TargetKind     string         `json:"target_kind"`
	Target         string         `json:"target"`
	Title          string         `json:"title"`
	Summary        string         `json:"summary"`
	Severity       string         `json:"severity"`
	EvidenceRefs   []string       `json:"evidence_refs"`
	Artifacts      map[string]any `json:"artifacts,omitempty"`
	ReplayManifest map[string]any `json:"replay_manifest,omitempty"`
}

type ValidationManualTestCase struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id,omitempty"`
	EngagementID string     `json:"engagement_id"`
	WSTGID       string     `json:"wstg_id,omitempty"`
	Category     string     `json:"category,omitempty"`
	Title        string     `json:"title"`
	Status       string     `json:"status"`
	AssignedTo   string     `json:"assigned_to,omitempty"`
	Notes        string     `json:"notes,omitempty"`
	EvidenceRefs []string   `json:"evidence_refs,omitempty"`
	CompletedBy  string     `json:"completed_by,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	CreatedBy    string     `json:"created_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type CreateValidationManualTestCaseRequest struct {
	EngagementID string   `json:"engagement_id"`
	WSTGID       string   `json:"wstg_id"`
	Category     string   `json:"category"`
	Title        string   `json:"title"`
	Status       string   `json:"status"`
	AssignedTo   string   `json:"assigned_to"`
	Notes        string   `json:"notes"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type ValidationExecutionEnvelope struct {
	ID                   string     `json:"id"`
	TenantID             string     `json:"tenant_id,omitempty"`
	EngagementID         string     `json:"engagement_id"`
	Status               string     `json:"status"`
	PolicyPackRef        string     `json:"policy_pack_ref,omitempty"`
	AllowedTools         []string   `json:"allowed_tools,omitempty"`
	RequiresStepApproval bool       `json:"requires_step_approval"`
	MaxRuntimeSeconds    int64      `json:"max_runtime_seconds,omitempty"`
	NetworkScope         string     `json:"network_scope,omitempty"`
	Notes                string     `json:"notes,omitempty"`
	CreatedBy            string     `json:"created_by,omitempty"`
	ApprovedBy           string     `json:"approved_by,omitempty"`
	ApprovedAt           *time.Time `json:"approved_at,omitempty"`
	ActivatedBy          string     `json:"activated_by,omitempty"`
	ActivatedAt          *time.Time `json:"activated_at,omitempty"`
	ClosedBy             string     `json:"closed_by,omitempty"`
	ClosedAt             *time.Time `json:"closed_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

type UpsertValidationExecutionEnvelopeRequest struct {
	PolicyPackRef        string   `json:"policy_pack_ref"`
	AllowedTools         []string `json:"allowed_tools"`
	RequiresStepApproval *bool    `json:"requires_step_approval"`
	MaxRuntimeSeconds    *int64   `json:"max_runtime_seconds"`
	NetworkScope         string   `json:"network_scope"`
	Notes                string   `json:"notes"`
}

type ValidationPlanStep struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id,omitempty"`
	EngagementID string     `json:"engagement_id"`
	Name         string     `json:"name"`
	AdapterID    string     `json:"adapter_id,omitempty"`
	TargetKind   string     `json:"target_kind,omitempty"`
	Target       string     `json:"target,omitempty"`
	DependsOn    []string   `json:"depends_on,omitempty"`
	Status       string     `json:"status"`
	RequestedBy  string     `json:"requested_by,omitempty"`
	DecidedBy    string     `json:"decided_by,omitempty"`
	Reason       string     `json:"reason,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
}

type CreateValidationPlanStepRequest struct {
	EngagementID string   `json:"engagement_id"`
	Name         string   `json:"name"`
	AdapterID    string   `json:"adapter_id"`
	TargetKind   string   `json:"target_kind"`
	Target       string   `json:"target"`
	DependsOn    []string `json:"depends_on"`
}

type ValidationPlanStepDecisionRequest struct {
	Reason string `json:"reason"`
}

type UpdateValidationManualTestCaseRequest struct {
	WSTGID       string   `json:"wstg_id"`
	Category     string   `json:"category"`
	Title        string   `json:"title"`
	Status       string   `json:"status"`
	AssignedTo   string   `json:"assigned_to"`
	Notes        string   `json:"notes"`
	EvidenceRefs []string `json:"evidence_refs"`
}
