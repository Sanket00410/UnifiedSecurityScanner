package models

type SyncOWASPMappingRequest struct {
	Limit      int      `json:"limit"`
	Frameworks []string `json:"frameworks"`
	Overwrite  bool     `json:"overwrite"`
}

type OWASPMappingSyncResult struct {
	ProcessedFindings int64            `json:"processed_findings"`
	CreatedMappings   int64            `json:"created_mappings"`
	UpdatedMappings   int64            `json:"updated_mappings"`
	SkippedFindings   int64            `json:"skipped_findings"`
	FrameworkTotals   map[string]int64 `json:"framework_totals"`
}
