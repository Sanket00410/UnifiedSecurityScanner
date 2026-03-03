package models

import "time"

type CanonicalFinding struct {
	SchemaVersion   string                `json:"schema_version"`
	FindingID       string                `json:"finding_id"`
	Fingerprint     string                `json:"fingerprint,omitempty"`
	TenantID        string                `json:"tenant_id"`
	Scanner         CanonicalScannerInfo  `json:"scanner"`
	Source          CanonicalSourceInfo   `json:"source"`
	Category        string                `json:"category"`
	Title           string                `json:"title"`
	Description     string                `json:"description,omitempty"`
	Severity        string                `json:"severity"`
	Confidence      string                `json:"confidence"`
	Status          string                `json:"status"`
	FirstSeenAt     time.Time             `json:"first_seen_at"`
	LastSeenAt      time.Time             `json:"last_seen_at"`
	Asset           CanonicalAssetInfo    `json:"asset"`
	Locations       []CanonicalLocation   `json:"locations,omitempty"`
	Evidence        []CanonicalEvidence   `json:"evidence,omitempty"`
	Risk            CanonicalRisk         `json:"risk"`
	Remediation     *CanonicalRemediation `json:"remediation,omitempty"`
	OccurrenceCount int64                 `json:"occurrence_count,omitempty"`
	ReopenedCount   int64                 `json:"reopened_count,omitempty"`
	Tags            []string              `json:"tags,omitempty"`
}

type CanonicalScannerInfo struct {
	Engine        string `json:"engine"`
	AdapterID     string `json:"adapter_id"`
	EngineVersion string `json:"engine_version,omitempty"`
	ScanJobID     string `json:"scan_job_id"`
}

type CanonicalSourceInfo struct {
	Layer string `json:"layer"`
	Tool  string `json:"tool"`
}

type CanonicalAssetInfo struct {
	AssetID     string `json:"asset_id"`
	AssetType   string `json:"asset_type"`
	AssetName   string `json:"asset_name"`
	Environment string `json:"environment"`
	Exposure    string `json:"exposure"`
	OwnerTeam   string `json:"owner_team,omitempty"`
}

type CanonicalLocation struct {
	Kind     string `json:"kind,omitempty"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Method   string `json:"method,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

type CanonicalEvidence struct {
	Kind    string `json:"kind"`
	Ref     string `json:"ref"`
	Summary string `json:"summary,omitempty"`
}

type CanonicalRisk struct {
	Priority                     string     `json:"priority"`
	OverallScore                 float64    `json:"overall_score"`
	BusinessImpact               float64    `json:"business_impact"`
	Exploitability               float64    `json:"exploitability"`
	Reachability                 float64    `json:"reachability"`
	Exposure                     float64    `json:"exposure"`
	AssetCriticality             float64    `json:"asset_criticality"`
	PolicyImpact                 float64    `json:"policy_impact"`
	CompensatingControlReduction float64    `json:"compensating_control_reduction,omitempty"`
	SLAClass                     string     `json:"sla_class"`
	SLADueAt                     *time.Time `json:"sla_due_at,omitempty"`
}

type CanonicalRemediation struct {
	Summary      string   `json:"summary,omitempty"`
	FixAvailable bool     `json:"fix_available"`
	References   []string `json:"references,omitempty"`
}

type TaskResultSubmission struct {
	TaskID           string
	WorkerID         string
	FinalState       string
	EvidencePaths    []string
	ErrorMessage     string
	ReportedFindings []CanonicalFinding
}
