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
