package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
	"unifiedsecurityscanner/control-plane/internal/risk"
)

type findingWaiverState struct {
	waiver            models.FindingWaiver
	remediationStatus string
	policyStatus      string
}

func (s *Store) ListFindingWaiversForTenant(ctx context.Context, organizationID string, findingID string, limit int) ([]models.FindingWaiver, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	items, err := s.loadFindingWaiverStates(ctx, strings.TrimSpace(organizationID), strings.TrimSpace(findingID))
	if err != nil {
		return nil, err
	}

	out := make([]models.FindingWaiver, 0, len(items))
	now := time.Now().UTC()
	for _, item := range items {
		waiver := item.waiver
		waiver.Status = deriveWaiverStatus(waiver, item.remediationStatus, item.policyStatus, now)
		out = append(out, waiver)
		if len(out) >= limit {
			break
		}
	}

	return out, nil
}

func (s *Store) CreateFindingWaiverForTenant(ctx context.Context, organizationID string, findingID string, request models.CreateFindingWaiverRequest) (models.FindingWaiver, error) {
	now := time.Now().UTC()
	findingID = strings.TrimSpace(findingID)
	if findingID == "" || strings.TrimSpace(request.RemediationID) == "" || strings.TrimSpace(request.Reason) == "" || request.Reduction <= 0 {
		return models.FindingWaiver{}, ErrInvalidWaiver
	}
	if request.ExpiresAt != nil && !request.ExpiresAt.After(now) {
		return models.FindingWaiver{}, ErrInvalidWaiver
	}

	var remediationStatus string
	err := s.pool.QueryRow(ctx, `
		SELECT status
		FROM remediation_actions
		WHERE tenant_id = $1
		  AND id = $2
		  AND finding_id = $3
	`, strings.TrimSpace(organizationID), strings.TrimSpace(request.RemediationID), findingID).Scan(&remediationStatus)
	if err != nil {
		if isNoRows(err) {
			return models.FindingWaiver{}, ErrInvalidWaiver
		}
		return models.FindingWaiver{}, fmt.Errorf("load remediation for finding waiver: %w", err)
	}

	policyStatus := ""
	if strings.TrimSpace(request.PolicyApprovalID) != "" {
		err := s.pool.QueryRow(ctx, `
			SELECT status
			FROM policy_approvals
			WHERE tenant_id = $1
			  AND id = $2
		`, strings.TrimSpace(organizationID), strings.TrimSpace(request.PolicyApprovalID)).Scan(&policyStatus)
		if err != nil {
			if isNoRows(err) {
				return models.FindingWaiver{}, ErrInvalidWaiver
			}
			return models.FindingWaiver{}, fmt.Errorf("load policy approval for finding waiver: %w", err)
		}
	}

	waiver := models.FindingWaiver{
		ID:               nextWaiverID(),
		TenantID:         strings.TrimSpace(organizationID),
		FindingID:        findingID,
		RemediationID:    strings.TrimSpace(request.RemediationID),
		PolicyApprovalID: strings.TrimSpace(request.PolicyApprovalID),
		Reason:           strings.TrimSpace(request.Reason),
		Reduction:        clampWaiverReduction(request.Reduction),
		Status:           "pending",
		ExpiresAt:        request.ExpiresAt,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	waiver.Status = deriveWaiverStatus(waiver, remediationStatus, policyStatus, now)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO finding_waivers (
			id, tenant_id, finding_id, remediation_id, policy_approval_id, reason, reduction, status, expires_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10
		)
	`, waiver.ID, waiver.TenantID, waiver.FindingID, waiver.RemediationID, waiver.PolicyApprovalID, waiver.Reason, waiver.Reduction, waiver.Status, waiver.ExpiresAt, now)
	if err != nil {
		return models.FindingWaiver{}, fmt.Errorf("insert finding waiver: %w", err)
	}

	return waiver, nil
}

func (s *Store) ListRiskSummaryForTenant(ctx context.Context, organizationID string) (models.RiskSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT finding_json
		FROM normalized_findings
		WHERE tenant_id = $1
	`, strings.TrimSpace(organizationID))
	if err != nil {
		return models.RiskSummary{}, fmt.Errorf("list risk summary findings: %w", err)
	}
	defer rows.Close()

	findings := make([]models.CanonicalFinding, 0)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return models.RiskSummary{}, fmt.Errorf("scan risk summary finding: %w", err)
		}

		var finding models.CanonicalFinding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return models.RiskSummary{}, fmt.Errorf("unmarshal risk summary finding: %w", err)
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return models.RiskSummary{}, fmt.Errorf("iterate risk summary findings: %w", err)
	}

	findings, err = s.applyEffectiveRiskAdjustments(ctx, strings.TrimSpace(organizationID), findings)
	if err != nil {
		return models.RiskSummary{}, err
	}

	summary := models.RiskSummary{
		GeneratedAt:    time.Now().UTC(),
		PriorityCounts: map[string]int64{"p0": 0, "p1": 0, "p2": 0, "p3": 0, "p4": 0},
		AgingBuckets:   map[string]int64{"0-6d": 0, "7-30d": 0, "31-89d": 0, "90d+": 0},
	}

	var ageTotal int64
	cutoff := summary.GeneratedAt.Add(-7 * 24 * time.Hour)
	for _, finding := range findings {
		summary.TotalFindings++
		if _, ok := summary.PriorityCounts[finding.Risk.Priority]; !ok {
			summary.PriorityCounts[finding.Risk.Priority] = 0
		}
		summary.PriorityCounts[finding.Risk.Priority]++
		if _, ok := summary.AgingBuckets[finding.Risk.AgingBucket]; !ok {
			summary.AgingBuckets[finding.Risk.AgingBucket] = 0
		}
		summary.AgingBuckets[finding.Risk.AgingBucket]++
		if finding.Risk.Overdue {
			summary.OverdueFindings++
		}
		if finding.ReopenedCount > 0 {
			summary.ReopenedFindings++
		}
		if !finding.FirstSeenAt.IsZero() && !finding.FirstSeenAt.Before(cutoff) {
			summary.NewFindings7d++
		}
		ageTotal += finding.Risk.AgeDays
	}

	if summary.TotalFindings > 0 {
		summary.AverageAgeDays = float64(ageTotal) / float64(summary.TotalFindings)
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM finding_occurrences
		WHERE tenant_id = $1
		  AND observed_at >= $2
	`, strings.TrimSpace(organizationID), cutoff).Scan(&summary.Observations7d); err != nil {
		return models.RiskSummary{}, fmt.Errorf("count risk observations: %w", err)
	}

	return summary, nil
}

func (s *Store) applyEffectiveRiskAdjustments(ctx context.Context, tenantID string, findings []models.CanonicalFinding) ([]models.CanonicalFinding, error) {
	if len(findings) == 0 {
		return findings, nil
	}

	reductions, err := s.loadActiveWaiverReductions(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	out := make([]models.CanonicalFinding, 0, len(findings))
	for _, finding := range findings {
		if reduction, ok := reductions[strings.TrimSpace(finding.FindingID)]; ok && reduction > 0 {
			finding = risk.ApplyWaiverReduction(finding, reduction)
		}
		finding = risk.ApplyTemporalSignals(finding, now)
		out = append(out, finding)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Risk.OverallScore == out[j].Risk.OverallScore {
			return out[i].LastSeenAt.After(out[j].LastSeenAt)
		}
		return out[i].Risk.OverallScore > out[j].Risk.OverallScore
	})

	return out, nil
}

func (s *Store) loadActiveWaiverReductions(ctx context.Context, tenantID string) (map[string]float64, error) {
	items, err := s.loadFindingWaiverStates(ctx, tenantID, "")
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	out := make(map[string]float64, len(items))
	for _, item := range items {
		if deriveWaiverStatus(item.waiver, item.remediationStatus, item.policyStatus, now) != "approved" {
			continue
		}
		out[item.waiver.FindingID] += clampWaiverReduction(item.waiver.Reduction)
		if out[item.waiver.FindingID] > 40 {
			out[item.waiver.FindingID] = 40
		}
	}

	return out, nil
}

func (s *Store) loadFindingWaiverStates(ctx context.Context, tenantID string, findingID string) ([]findingWaiverState, error) {
	query := `
		SELECT fw.id, fw.tenant_id, fw.finding_id, fw.remediation_id, fw.policy_approval_id, fw.reason,
		       fw.reduction, fw.status, fw.expires_at, fw.created_at, fw.updated_at,
		       COALESCE(ra.status, ''), COALESCE(pa.status, '')
		FROM finding_waivers fw
		LEFT JOIN remediation_actions ra ON ra.tenant_id = fw.tenant_id AND ra.id = fw.remediation_id
		LEFT JOIN policy_approvals pa ON pa.tenant_id = fw.tenant_id AND pa.id = fw.policy_approval_id
		WHERE fw.tenant_id = $1
	`
	args := []any{tenantID}
	if findingID != "" {
		query += " AND fw.finding_id = $2"
		args = append(args, findingID)
	}
	query += " ORDER BY fw.updated_at DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list finding waivers: %w", err)
	}
	defer rows.Close()

	out := make([]findingWaiverState, 0)
	for rows.Next() {
		var item findingWaiverState
		if err := rows.Scan(
			&item.waiver.ID,
			&item.waiver.TenantID,
			&item.waiver.FindingID,
			&item.waiver.RemediationID,
			&item.waiver.PolicyApprovalID,
			&item.waiver.Reason,
			&item.waiver.Reduction,
			&item.waiver.Status,
			&item.waiver.ExpiresAt,
			&item.waiver.CreatedAt,
			&item.waiver.UpdatedAt,
			&item.remediationStatus,
			&item.policyStatus,
		); err != nil {
			return nil, fmt.Errorf("scan finding waiver: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding waivers: %w", err)
	}

	return out, nil
}

func deriveWaiverStatus(waiver models.FindingWaiver, remediationStatus string, policyStatus string, now time.Time) string {
	if waiver.ExpiresAt != nil && !waiver.ExpiresAt.After(now) {
		return "expired"
	}
	if strings.TrimSpace(waiver.RemediationID) != "" && !strings.EqualFold(strings.TrimSpace(remediationStatus), "accepted_risk") {
		return "pending"
	}
	if strings.TrimSpace(waiver.PolicyApprovalID) != "" && !strings.EqualFold(strings.TrimSpace(policyStatus), "approved") {
		return "pending"
	}
	return "approved"
}

func clampWaiverReduction(value float64) float64 {
	switch {
	case value <= 0:
		return 0
	case value > 40:
		return 40
	default:
		return value
	}
}
