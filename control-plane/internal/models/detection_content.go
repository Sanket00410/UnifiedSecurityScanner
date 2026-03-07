package models

import "time"

type DetectionRulepack struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id,omitempty"`
	Name           string    `json:"name"`
	Engine         string    `json:"engine"`
	Status         string    `json:"status"`
	Description    string    `json:"description,omitempty"`
	CurrentVersion string    `json:"current_version,omitempty"`
	CreatedBy      string    `json:"created_by,omitempty"`
	UpdatedBy      string    `json:"updated_by,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type CreateDetectionRulepackRequest struct {
	Name        string `json:"name"`
	Engine      string `json:"engine"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

type UpdateDetectionRulepackRequest struct {
	Name        string `json:"name"`
	Engine      string `json:"engine"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

type DetectionRulepackVersion struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id,omitempty"`
	RulepackID   string     `json:"rulepack_id"`
	VersionTag   string     `json:"version_tag"`
	ContentRef   string     `json:"content_ref,omitempty"`
	Checksum     string     `json:"checksum,omitempty"`
	Status       string     `json:"status"`
	QualityScore float64    `json:"quality_score"`
	PublishedBy  string     `json:"published_by,omitempty"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type CreateDetectionRulepackVersionRequest struct {
	VersionTag   string  `json:"version_tag"`
	ContentRef   string  `json:"content_ref"`
	Checksum     string  `json:"checksum"`
	Status       string  `json:"status"`
	QualityScore float64 `json:"quality_score"`
}

type PromoteDetectionRulepackVersionRequest struct {
	Phase       string `json:"phase"`
	TargetScope string `json:"target_scope"`
	Notes       string `json:"notes"`
}

type DetectionRulepackRollout struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id,omitempty"`
	RulepackID  string     `json:"rulepack_id"`
	VersionID   string     `json:"version_id"`
	Phase       string     `json:"phase"`
	Status      string     `json:"status"`
	TargetScope string     `json:"target_scope,omitempty"`
	Notes       string     `json:"notes,omitempty"`
	StartedBy   string     `json:"started_by,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}
