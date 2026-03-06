package models

import "time"

type ScanEngineControl struct {
	TenantID          string    `json:"tenant_id"`
	AdapterID         string    `json:"adapter_id"`
	TargetKind        string    `json:"target_kind,omitempty"`
	Enabled           bool      `json:"enabled"`
	RulepackVersion   string    `json:"rulepack_version,omitempty"`
	MaxRuntimeSeconds int64     `json:"max_runtime_seconds,omitempty"`
	UpdatedBy         string    `json:"updated_by,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type UpsertScanEngineControlRequest struct {
	TargetKind        string  `json:"target_kind"`
	Enabled           *bool   `json:"enabled"`
	RulepackVersion   *string `json:"rulepack_version"`
	MaxRuntimeSeconds *int64  `json:"max_runtime_seconds"`
}
