package jobs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) GetSAMMMetricsForTenant(ctx context.Context, tenantID string) (models.SAMMMetrics, error) {
	tenantID = strings.TrimSpace(tenantID)
	now := time.Now().UTC()

	metrics := models.SAMMMetrics{
		StatusTotals: map[string]int64{
			"identified":     0,
			"planned":        0,
			"implemented":    0,
			"verified":       0,
			"not_applicable": 0,
		},
		Categories:  []models.SAMMCategoryMetrics{},
		GeneratedAt: now,
	}

	rows, err := s.pool.Query(ctx, `
		SELECT category, status, COUNT(*)
		FROM compliance_control_mappings
		WHERE tenant_id = $1
		  AND framework = 'samm'
		GROUP BY category, status
	`, tenantID)
	if err != nil {
		return models.SAMMMetrics{}, fmt.Errorf("load samm metrics groups: %w", err)
	}
	defer rows.Close()

	type aggregate struct {
		total      int64
		gapCount   int64
		considered int64
		weighted   float64
		statuses   map[string]int64
	}

	byCategory := map[string]*aggregate{}
	for rows.Next() {
		var (
			category string
			status   string
			count    int64
		)
		if err := rows.Scan(&category, &status, &count); err != nil {
			return models.SAMMMetrics{}, fmt.Errorf("scan samm metrics group: %w", err)
		}

		category = strings.TrimSpace(category)
		if category == "" {
			category = "unmapped"
		}
		status = normalizeComplianceStatus(status)
		if status == "" {
			continue
		}

		entry, exists := byCategory[category]
		if !exists {
			entry = &aggregate{statuses: map[string]int64{}}
			byCategory[category] = entry
		}

		entry.total += count
		entry.statuses[status] += count
		metrics.TotalControls += count
		metrics.StatusTotals[status] += count

		if status == "identified" || status == "planned" {
			entry.gapCount += count
		}

		weight, considered := sammStatusWeight(status)
		if considered {
			entry.considered += count
			entry.weighted += weight * float64(count)
			metrics.ConsideredControlSize += count
			metrics.OverallMaturityScore += weight * float64(count)
		}
	}
	if err := rows.Err(); err != nil {
		return models.SAMMMetrics{}, fmt.Errorf("iterate samm metrics groups: %w", err)
	}

	categoryNames := make([]string, 0, len(byCategory))
	for category := range byCategory {
		categoryNames = append(categoryNames, category)
	}
	sort.Strings(categoryNames)

	metrics.Categories = make([]models.SAMMCategoryMetrics, 0, len(categoryNames))
	for _, category := range categoryNames {
		entry := byCategory[category]
		score := 0.0
		if entry.considered > 0 {
			score = entry.weighted / float64(entry.considered)
		}
		metrics.Categories = append(metrics.Categories, models.SAMMCategoryMetrics{
			Category:      category,
			TotalControls: entry.total,
			StatusTotals:  entry.statuses,
			GapCount:      entry.gapCount,
			MaturityScore: score,
		})
	}

	if metrics.ConsideredControlSize > 0 {
		metrics.OverallMaturityScore = metrics.OverallMaturityScore / float64(metrics.ConsideredControlSize)
	}

	return metrics, nil
}

func sammStatusWeight(status string) (float64, bool) {
	switch normalizeComplianceStatus(status) {
	case "identified":
		return 1.0, true
	case "planned":
		return 2.0, true
	case "implemented":
		return 3.0, true
	case "verified":
		return 4.0, true
	default:
		return 0, false
	}
}
