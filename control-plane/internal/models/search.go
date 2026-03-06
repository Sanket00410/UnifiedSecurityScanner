package models

type FindingSearchQuery struct {
	Query    string `json:"query,omitempty"`
	Severity string `json:"severity,omitempty"`
	Priority string `json:"priority,omitempty"`
	Layer    string `json:"layer,omitempty"`
	Status   string `json:"status,omitempty"`
	Overdue  *bool  `json:"overdue,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}

type FindingSearchResult struct {
	Items  []CanonicalFinding `json:"items"`
	Total  int64              `json:"total"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
}
