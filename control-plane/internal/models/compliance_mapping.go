package models

import "time"

type ComplianceControlMapping struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id,omitempty"`
	SourceKind   string    `json:"source_kind"`
	SourceID     string    `json:"source_id"`
	FindingID    string    `json:"finding_id,omitempty"`
	Framework    string    `json:"framework"`
	Category     string    `json:"category,omitempty"`
	ControlID    string    `json:"control_id"`
	ControlTitle string    `json:"control_title,omitempty"`
	Status       string    `json:"status"`
	EvidenceRef  string    `json:"evidence_ref,omitempty"`
	Notes        string    `json:"notes,omitempty"`
	CreatedBy    string    `json:"created_by,omitempty"`
	UpdatedBy    string    `json:"updated_by,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CreateComplianceControlMappingRequest struct {
	SourceKind   string `json:"source_kind"`
	SourceID     string `json:"source_id"`
	FindingID    string `json:"finding_id"`
	Framework    string `json:"framework"`
	Category     string `json:"category"`
	ControlID    string `json:"control_id"`
	ControlTitle string `json:"control_title"`
	Status       string `json:"status"`
	EvidenceRef  string `json:"evidence_ref"`
	Notes        string `json:"notes"`
}

type UpdateComplianceControlMappingRequest struct {
	Framework    string `json:"framework"`
	Category     string `json:"category"`
	ControlID    string `json:"control_id"`
	ControlTitle string `json:"control_title"`
	Status       string `json:"status"`
	EvidenceRef  string `json:"evidence_ref"`
	Notes        string `json:"notes"`
}

type ComplianceSummary struct {
	TotalMappings   int64                       `json:"total_mappings"`
	FrameworkTotals map[string]int64            `json:"framework_totals"`
	StatusTotals    map[string]int64            `json:"status_totals"`
	FrameworkStatus map[string]map[string]int64 `json:"framework_status"`
	LastUpdatedAt   *time.Time                  `json:"last_updated_at,omitempty"`
}
