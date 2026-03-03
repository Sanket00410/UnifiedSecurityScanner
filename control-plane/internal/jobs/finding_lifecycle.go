package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
	"unifiedsecurityscanner/control-plane/internal/risk"
)

func persistFindingTx(ctx context.Context, tx pgx.Tx, task models.TaskContext, finding models.CanonicalFinding, now time.Time, envelope assetRiskEnvelope) error {
	if strings.TrimSpace(finding.SchemaVersion) == "" {
		finding.SchemaVersion = "1.0.0"
	}
	if strings.TrimSpace(finding.TenantID) == "" {
		finding.TenantID = task.TenantID
	}
	if strings.TrimSpace(finding.Scanner.Engine) == "" {
		finding.Scanner.Engine = task.AdapterID
	}
	if strings.TrimSpace(finding.Scanner.AdapterID) == "" {
		finding.Scanner.AdapterID = task.AdapterID
	}
	if strings.TrimSpace(finding.Scanner.ScanJobID) == "" {
		finding.Scanner.ScanJobID = task.ScanJobID
	}
	if strings.TrimSpace(finding.Source.Tool) == "" {
		finding.Source.Tool = task.AdapterID
	}
	if strings.TrimSpace(finding.Asset.AssetID) == "" {
		finding.Asset.AssetID = task.Target
	}
	if strings.TrimSpace(finding.Asset.AssetType) == "" {
		finding.Asset.AssetType = task.TargetKind
	}
	if strings.TrimSpace(finding.Asset.AssetName) == "" {
		finding.Asset.AssetName = task.Target
	}
	if finding.FirstSeenAt.IsZero() {
		finding.FirstSeenAt = now
	}
	finding.LastSeenAt = now
	if strings.TrimSpace(finding.Status) == "" {
		finding.Status = "open"
	}

	finding = risk.EnrichWithInputs(finding, riskInputsForFinding(finding, envelope))
	findingKey := risk.Fingerprint(finding)
	finding.Fingerprint = findingKey
	if strings.TrimSpace(finding.FindingID) == "" {
		finding.FindingID = risk.StableFindingID(findingKey)
	}

	row := tx.QueryRow(ctx, `
		SELECT finding_id, finding_json, occurrence_count, reopened_count, current_status
		FROM normalized_findings
		WHERE tenant_id = $1
		  AND finding_key = $2
		FOR UPDATE
	`, task.TenantID, findingKey)

	var existingFindingID string
	var existingPayload []byte
	var occurrenceCount int64
	var reopenedCount int64
	var currentStatus string

	err := row.Scan(&existingFindingID, &existingPayload, &occurrenceCount, &reopenedCount, &currentStatus)
	if err != nil && !isNoRows(err) {
		return fmt.Errorf("load existing normalized finding: %w", err)
	}

	if err == nil {
		var existingFinding models.CanonicalFinding
		if len(existingPayload) > 0 {
			if err := json.Unmarshal(existingPayload, &existingFinding); err != nil {
				return fmt.Errorf("decode existing normalized finding: %w", err)
			}
		}

		if !existingFinding.FirstSeenAt.IsZero() {
			finding.FirstSeenAt = existingFinding.FirstSeenAt
		}
		if existingFinding.OccurrenceCount > occurrenceCount {
			occurrenceCount = existingFinding.OccurrenceCount
		}
		if existingFinding.ReopenedCount > reopenedCount {
			reopenedCount = existingFinding.ReopenedCount
		}
		if strings.TrimSpace(existingFinding.Asset.OwnerTeam) != "" && strings.TrimSpace(finding.Asset.OwnerTeam) == "" {
			finding.Asset.OwnerTeam = existingFinding.Asset.OwnerTeam
		}

		occurrenceCount++
		if shouldReopenFinding(currentStatus, finding.Status) {
			reopenedCount++
		}
		finding.FindingID = existingFindingID
		finding.OccurrenceCount = occurrenceCount
		finding.ReopenedCount = reopenedCount
		finding = risk.ApplyTemporalSignals(finding, now)

		payload, err := json.Marshal(finding)
		if err != nil {
			return fmt.Errorf("marshal updated normalized finding: %w", err)
		}

		_, err = tx.Exec(ctx, `
			UPDATE normalized_findings
			SET scan_job_id = $2,
			    task_id = $3,
			    adapter_id = $4,
			    finding_json = $5,
			    updated_at = $6,
			    occurrence_count = $7,
			    reopened_count = $8,
			    current_status = $9
			WHERE finding_id = $1
		`, existingFindingID, task.ScanJobID, task.TaskID, task.AdapterID, payload, now, occurrenceCount, reopenedCount, normalizeStoredFindingStatus(finding.Status))
		if err != nil {
			return fmt.Errorf("update normalized finding: %w", err)
		}

		return recordFindingOccurrenceTx(ctx, tx, task, finding, findingKey, now)
	}

	finding.OccurrenceCount = 1
	finding.ReopenedCount = 0
	finding.FindingID = risk.StableFindingID(findingKey)
	finding = risk.ApplyTemporalSignals(finding, now)

	payload, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("marshal normalized finding: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO normalized_findings (
			finding_id, finding_key, scan_job_id, task_id, tenant_id, adapter_id, finding_json,
			occurrence_count, reopened_count, current_status, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $11
		)
	`, finding.FindingID, findingKey, task.ScanJobID, task.TaskID, task.TenantID, task.AdapterID, payload, finding.OccurrenceCount, finding.ReopenedCount, normalizeStoredFindingStatus(finding.Status), now)
	if err != nil {
		return fmt.Errorf("insert normalized finding: %w", err)
	}

	return recordFindingOccurrenceTx(ctx, tx, task, finding, findingKey, now)
}

func shouldReopenFinding(currentStatus string, nextStatus string) bool {
	nextStatus = normalizeStoredFindingStatus(nextStatus)
	if nextStatus != "open" {
		return false
	}

	switch normalizeStoredFindingStatus(currentStatus) {
	case "resolved", "accepted", "suppressed", "closed":
		return true
	default:
		return false
	}
}

func normalizeStoredFindingStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "triaged":
		return "triaged"
	case "suppressed":
		return "suppressed"
	case "accepted":
		return "accepted"
	case "resolved":
		return "resolved"
	case "closed":
		return "closed"
	default:
		return "open"
	}
}

func recordFindingOccurrenceTx(ctx context.Context, tx pgx.Tx, task models.TaskContext, finding models.CanonicalFinding, findingKey string, observedAt time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO finding_occurrences (
			id, tenant_id, finding_id, finding_key, scan_job_id, task_id, observed_status, observed_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $8
		)
	`, nextOccurrenceID(), task.TenantID, finding.FindingID, findingKey, task.ScanJobID, task.TaskID, normalizeStoredFindingStatus(finding.Status), observedAt)
	if err != nil {
		return fmt.Errorf("insert finding occurrence: %w", err)
	}

	return nil
}
