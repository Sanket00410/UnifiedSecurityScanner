package models

import (
	"time"

	controlmodels "unifiedsecurityscanner/control-plane/internal/models"
)

type ScoreInputs struct {
	EnvironmentOverride          string     `json:"environment_override,omitempty"`
	ExposureOverride             string     `json:"exposure_override,omitempty"`
	AssetCriticalityOverride     float64    `json:"asset_criticality_override,omitempty"`
	OwnerTeam                    string     `json:"owner_team,omitempty"`
	OwnerHierarchy               []string   `json:"owner_hierarchy,omitempty"`
	ServiceName                  string     `json:"service_name,omitempty"`
	ServiceTier                  string     `json:"service_tier,omitempty"`
	ServiceCriticalityClass      string     `json:"service_criticality_class,omitempty"`
	ExternalSource               string     `json:"external_source,omitempty"`
	ExternalReference            string     `json:"external_reference,omitempty"`
	LastSyncedAt                 *time.Time `json:"last_synced_at,omitempty"`
	CompensatingControlReduction float64    `json:"compensating_control_reduction,omitempty"`
	WaiverReduction              float64    `json:"waiver_reduction,omitempty"`
}

type ScoreRequest struct {
	Finding       controlmodels.CanonicalFinding `json:"finding"`
	Inputs        ScoreInputs                    `json:"inputs,omitempty"`
	ReferenceTime *time.Time                     `json:"reference_time,omitempty"`
}

type ScoreResponse struct {
	Finding controlmodels.CanonicalFinding `json:"finding"`
}

type BatchScoreRequest struct {
	Items []ScoreRequest `json:"items"`
}

type BatchScoreResponse struct {
	Items []ScoreResponse `json:"items"`
}

type QueueDescriptor struct {
	Priority string `json:"priority"`
	SLAClass string `json:"sla_class"`
	Queue    string `json:"queue"`
}
