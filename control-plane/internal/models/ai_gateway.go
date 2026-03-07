package models

import "time"

type AIGatewayPolicy struct {
	TenantID            string    `json:"tenant_id,omitempty"`
	DefaultModel        string    `json:"default_model"`
	AllowedModels       []string  `json:"allowed_models,omitempty"`
	MaxInputChars       int64     `json:"max_input_chars"`
	MaxOutputChars      int64     `json:"max_output_chars"`
	RequireGrounding    bool      `json:"require_grounding"`
	RequireEvidenceRefs bool      `json:"require_evidence_refs"`
	RedactSecrets       bool      `json:"redact_secrets"`
	UpdatedBy           string    `json:"updated_by,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type UpsertAIGatewayPolicyRequest struct {
	DefaultModel        string   `json:"default_model"`
	AllowedModels       []string `json:"allowed_models"`
	MaxInputChars       *int64   `json:"max_input_chars"`
	MaxOutputChars      *int64   `json:"max_output_chars"`
	RequireGrounding    *bool    `json:"require_grounding"`
	RequireEvidenceRefs *bool    `json:"require_evidence_refs"`
	RedactSecrets       *bool    `json:"redact_secrets"`
}

type AITriageRequest struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id,omitempty"`
	RequestKind  string    `json:"request_kind"`
	Model        string    `json:"model"`
	InputText    string    `json:"input_text"`
	EvidenceRefs []string  `json:"evidence_refs,omitempty"`
	FindingIDs   []string  `json:"finding_ids,omitempty"`
	ResponseText string    `json:"response_text"`
	SafetyState  string    `json:"safety_state"`
	CreatedBy    string    `json:"created_by,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type CreateAITriageSummaryRequest struct {
	Model          string   `json:"model"`
	InputText      string   `json:"input_text"`
	EvidenceRefs   []string `json:"evidence_refs"`
	FindingIDs     []string `json:"finding_ids"`
	MaxOutputChars *int64   `json:"max_output_chars"`
}
