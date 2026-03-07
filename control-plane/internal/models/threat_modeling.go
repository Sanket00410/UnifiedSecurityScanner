package models

import "time"

type DesignReview struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id,omitempty"`
	Title              string     `json:"title"`
	ServiceName        string     `json:"service_name,omitempty"`
	ServiceID          string     `json:"service_id,omitempty"`
	Status             string     `json:"status"`
	ThreatTemplate     string     `json:"threat_template,omitempty"`
	Summary            string     `json:"summary,omitempty"`
	DiagramRef         string     `json:"diagram_ref,omitempty"`
	DataClassification string     `json:"data_classification,omitempty"`
	DesignOwner        string     `json:"design_owner,omitempty"`
	Reviewer           string     `json:"reviewer,omitempty"`
	CreatedBy          string     `json:"created_by,omitempty"`
	UpdatedBy          string     `json:"updated_by,omitempty"`
	SubmittedAt        *time.Time `json:"submitted_at,omitempty"`
	ApprovedAt         *time.Time `json:"approved_at,omitempty"`
	ClosedAt           *time.Time `json:"closed_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type CreateDesignReviewRequest struct {
	Title              string `json:"title"`
	ServiceName        string `json:"service_name"`
	ServiceID          string `json:"service_id"`
	ThreatTemplate     string `json:"threat_template"`
	Summary            string `json:"summary"`
	DiagramRef         string `json:"diagram_ref"`
	DataClassification string `json:"data_classification"`
	DesignOwner        string `json:"design_owner"`
	Reviewer           string `json:"reviewer"`
}

type UpdateDesignReviewRequest struct {
	Title              string `json:"title"`
	ServiceName        string `json:"service_name"`
	ServiceID          string `json:"service_id"`
	ThreatTemplate     string `json:"threat_template"`
	Summary            string `json:"summary"`
	DiagramRef         string `json:"diagram_ref"`
	DataClassification string `json:"data_classification"`
	DesignOwner        string `json:"design_owner"`
	Reviewer           string `json:"reviewer"`
}

type DesignReviewDecisionRequest struct {
	Reason string `json:"reason"`
}

type DesignThreat struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id,omitempty"`
	ReviewID            string    `json:"review_id"`
	Category            string    `json:"category,omitempty"`
	Title               string    `json:"title"`
	Description         string    `json:"description,omitempty"`
	AbuseCase           string    `json:"abuse_case,omitempty"`
	Impact              string    `json:"impact,omitempty"`
	Likelihood          string    `json:"likelihood,omitempty"`
	Severity            string    `json:"severity,omitempty"`
	Status              string    `json:"status"`
	LinkedAssetID       string    `json:"linked_asset_id,omitempty"`
	LinkedFindingID     string    `json:"linked_finding_id,omitempty"`
	RuntimeEvidenceRefs []string  `json:"runtime_evidence_refs,omitempty"`
	Mitigation          string    `json:"mitigation,omitempty"`
	CreatedBy           string    `json:"created_by,omitempty"`
	UpdatedBy           string    `json:"updated_by,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type CreateDesignThreatRequest struct {
	Category            string   `json:"category"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	AbuseCase           string   `json:"abuse_case"`
	Impact              string   `json:"impact"`
	Likelihood          string   `json:"likelihood"`
	Severity            string   `json:"severity"`
	Status              string   `json:"status"`
	LinkedAssetID       string   `json:"linked_asset_id"`
	LinkedFindingID     string   `json:"linked_finding_id"`
	RuntimeEvidenceRefs []string `json:"runtime_evidence_refs"`
	Mitigation          string   `json:"mitigation"`
}

type UpdateDesignThreatRequest struct {
	Category            string   `json:"category"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	AbuseCase           string   `json:"abuse_case"`
	Impact              string   `json:"impact"`
	Likelihood          string   `json:"likelihood"`
	Severity            string   `json:"severity"`
	Status              string   `json:"status"`
	LinkedAssetID       string   `json:"linked_asset_id"`
	LinkedFindingID     string   `json:"linked_finding_id"`
	RuntimeEvidenceRefs []string `json:"runtime_evidence_refs"`
	Mitigation          string   `json:"mitigation"`
}

type DesignDataFlowModel struct {
	ID              string           `json:"id"`
	TenantID        string           `json:"tenant_id,omitempty"`
	ReviewID        string           `json:"review_id"`
	Entities        []map[string]any `json:"entities,omitempty"`
	Flows           []map[string]any `json:"flows,omitempty"`
	TrustBoundaries []map[string]any `json:"trust_boundaries,omitempty"`
	Notes           string           `json:"notes,omitempty"`
	UpdatedBy       string           `json:"updated_by,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

type UpsertDesignDataFlowRequest struct {
	Entities        []map[string]any `json:"entities"`
	Flows           []map[string]any `json:"flows"`
	TrustBoundaries []map[string]any `json:"trust_boundaries"`
	Notes           string           `json:"notes"`
}

type DesignControlMapping struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id,omitempty"`
	ReviewID     string    `json:"review_id"`
	ThreatID     string    `json:"threat_id,omitempty"`
	Framework    string    `json:"framework"`
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

type CreateDesignControlMappingRequest struct {
	ThreatID     string `json:"threat_id"`
	Framework    string `json:"framework"`
	ControlID    string `json:"control_id"`
	ControlTitle string `json:"control_title"`
	Status       string `json:"status"`
	EvidenceRef  string `json:"evidence_ref"`
	Notes        string `json:"notes"`
}

type UpdateDesignControlMappingRequest struct {
	ThreatID     string `json:"threat_id"`
	Framework    string `json:"framework"`
	ControlID    string `json:"control_id"`
	ControlTitle string `json:"control_title"`
	Status       string `json:"status"`
	EvidenceRef  string `json:"evidence_ref"`
	Notes        string `json:"notes"`
}
