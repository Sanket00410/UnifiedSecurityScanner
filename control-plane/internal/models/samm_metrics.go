package models

import "time"

type SAMMCategoryMetrics struct {
	Category      string           `json:"category"`
	TotalControls int64            `json:"total_controls"`
	StatusTotals  map[string]int64 `json:"status_totals"`
	GapCount      int64            `json:"gap_count"`
	MaturityScore float64          `json:"maturity_score"`
}

type SAMMMetrics struct {
	TotalControls         int64                 `json:"total_controls"`
	StatusTotals          map[string]int64      `json:"status_totals"`
	OverallMaturityScore  float64               `json:"overall_maturity_score"`
	Categories            []SAMMCategoryMetrics `json:"categories"`
	GeneratedAt           time.Time             `json:"generated_at"`
	ConsideredControlSize int64                 `json:"considered_control_size"`
}
