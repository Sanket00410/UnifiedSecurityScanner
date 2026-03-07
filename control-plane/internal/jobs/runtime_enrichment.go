package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListRuntimeFindingEnrichmentsForTenant(ctx context.Context, tenantID string, findingID string, limit int) ([]models.RuntimeFindingEnrichment, error) {
	tenantID = strings.TrimSpace(tenantID)
	findingID = strings.TrimSpace(findingID)
	if limit <= 0 || limit > 2000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, finding_id, telemetry_event_id, event_type, severity,
		       confidence_before, confidence_after, created_at
		FROM runtime_finding_enrichments
		WHERE tenant_id = $1
		  AND ($2 = '' OR finding_id = $2)
		ORDER BY created_at DESC, id DESC
		LIMIT $3
	`, tenantID, findingID, limit)
	if err != nil {
		return nil, fmt.Errorf("list runtime finding enrichments: %w", err)
	}
	defer rows.Close()

	items := make([]models.RuntimeFindingEnrichment, 0, limit)
	for rows.Next() {
		item, err := scanRuntimeFindingEnrichment(rows)
		if err != nil {
			return nil, fmt.Errorf("scan runtime finding enrichment row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runtime finding enrichment rows: %w", err)
	}

	return items, nil
}

func (s *Store) BackfillRuntimeFindingEnrichmentForTenant(ctx context.Context, tenantID string, limit int) (models.RuntimeEnrichmentBackfillResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	if limit <= 0 || limit > 5000 {
		limit = 500
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RuntimeEnrichmentBackfillResult{}, fmt.Errorf("begin runtime enrichment backfill tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT e.id, e.tenant_id, e.connector_id, e.source_kind, e.source_ref, e.asset_id,
		       e.finding_id, e.event_type, e.severity, e.observed_at, e.payload_json,
		       e.evidence_refs_json, e.created_at
		FROM runtime_telemetry_events e
		WHERE e.tenant_id = $1
		  AND COALESCE(e.finding_id, '') <> ''
		  AND NOT EXISTS (
		      SELECT 1
		      FROM runtime_finding_enrichments r
		      WHERE r.tenant_id = e.tenant_id
		        AND r.finding_id = e.finding_id
		        AND r.telemetry_event_id = e.id
		  )
		ORDER BY e.observed_at ASC, e.id ASC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return models.RuntimeEnrichmentBackfillResult{}, fmt.Errorf("query runtime enrichment backfill candidates: %w", err)
	}
	defer rows.Close()

	result := models.RuntimeEnrichmentBackfillResult{}
	for rows.Next() {
		event, err := scanRuntimeTelemetryEvent(rows)
		if err != nil {
			return models.RuntimeEnrichmentBackfillResult{}, fmt.Errorf("scan runtime enrichment backfill event: %w", err)
		}
		result.ProcessedEvents++
		enriched, err := enrichFindingFromRuntimeEventTx(ctx, tx, event)
		if err != nil {
			return models.RuntimeEnrichmentBackfillResult{}, err
		}
		if enriched {
			result.EnrichedFindings++
		} else {
			result.SkippedEvents++
		}
	}
	if err := rows.Err(); err != nil {
		return models.RuntimeEnrichmentBackfillResult{}, fmt.Errorf("iterate runtime enrichment backfill candidates: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RuntimeEnrichmentBackfillResult{}, fmt.Errorf("commit runtime enrichment backfill tx: %w", err)
	}
	return result, nil
}

func enrichFindingFromRuntimeEventTx(ctx context.Context, tx pgx.Tx, event models.RuntimeTelemetryEvent) (bool, error) {
	tenantID := strings.TrimSpace(event.TenantID)
	findingID := strings.TrimSpace(event.FindingID)
	if tenantID == "" || findingID == "" {
		return false, nil
	}

	var alreadyExists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM runtime_finding_enrichments
			WHERE tenant_id = $1
			  AND finding_id = $2
			  AND telemetry_event_id = $3
		)
	`, tenantID, findingID, strings.TrimSpace(event.ID)).Scan(&alreadyExists); err != nil {
		return false, fmt.Errorf("check runtime finding enrichment duplicate: %w", err)
	}
	if alreadyExists {
		return false, nil
	}

	var findingJSON []byte
	err := tx.QueryRow(ctx, `
		SELECT finding_json
		FROM normalized_findings
		WHERE tenant_id = $1
		  AND finding_id = $2
		FOR UPDATE
	`, tenantID, findingID).Scan(&findingJSON)
	if err != nil {
		if isNoRows(err) {
			return false, nil
		}
		return false, fmt.Errorf("load finding for runtime enrichment: %w", err)
	}

	var finding models.CanonicalFinding
	if err := json.Unmarshal(findingJSON, &finding); err != nil {
		return false, fmt.Errorf("decode finding for runtime enrichment: %w", err)
	}

	confidenceBefore := strings.ToLower(strings.TrimSpace(finding.Confidence))
	confidenceAfter := confidenceBefore
	switch strings.ToLower(strings.TrimSpace(event.Severity)) {
	case "critical", "high":
		confidenceAfter = "high"
	case "medium":
		if confidenceAfter == "" || confidenceAfter == "low" {
			confidenceAfter = "medium"
		}
	default:
		if confidenceAfter == "" {
			confidenceAfter = "medium"
		}
	}
	finding.Confidence = confidenceAfter

	if finding.LastSeenAt.IsZero() || event.ObservedAt.After(finding.LastSeenAt) {
		finding.LastSeenAt = event.ObservedAt
	}

	finding.Tags = appendCanonicalTag(finding.Tags, "runtime_confirmed")
	if eventTypeTag := normalizeRuntimeEventTag(event.EventType); eventTypeTag != "" {
		finding.Tags = appendCanonicalTag(finding.Tags, "runtime_event:"+eventTypeTag)
	}

	if len(event.EvidenceRefs) > 0 {
		for _, reference := range event.EvidenceRefs {
			reference = strings.TrimSpace(reference)
			if reference == "" {
				continue
			}
			if canonicalEvidenceContains(finding.Evidence, "runtime_telemetry", reference) {
				continue
			}
			finding.Evidence = append(finding.Evidence, models.CanonicalEvidence{
				Kind:    "runtime_telemetry",
				Ref:     reference,
				Summary: strings.TrimSpace(event.EventType),
			})
		}
	} else if strings.TrimSpace(event.SourceRef) != "" {
		fallbackRef := "runtime://" + strings.TrimSpace(event.SourceRef)
		if !canonicalEvidenceContains(finding.Evidence, "runtime_telemetry", fallbackRef) {
			finding.Evidence = append(finding.Evidence, models.CanonicalEvidence{
				Kind:    "runtime_telemetry",
				Ref:     fallbackRef,
				Summary: strings.TrimSpace(event.EventType),
			})
		}
	}

	if note := buildRuntimeConfirmationNote(event); note != "" && !strings.Contains(strings.ToLower(finding.Description), strings.ToLower(note)) {
		if strings.TrimSpace(finding.Description) == "" {
			finding.Description = note
		} else {
			finding.Description = strings.TrimSpace(finding.Description) + "\n\n" + note
		}
	}

	now := time.Now().UTC()
	updatedPayload, err := json.Marshal(finding)
	if err != nil {
		return false, fmt.Errorf("marshal finding for runtime enrichment: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE normalized_findings
		SET finding_json = $3,
		    updated_at = $4
		WHERE tenant_id = $1
		  AND finding_id = $2
	`, tenantID, findingID, updatedPayload, now)
	if err != nil {
		return false, fmt.Errorf("update finding for runtime enrichment: %w", err)
	}

	enrichment := models.RuntimeFindingEnrichment{
		ID:               nextRuntimeFindingEnrichmentID(),
		TenantID:         tenantID,
		FindingID:        findingID,
		TelemetryEventID: strings.TrimSpace(event.ID),
		EventType:        strings.TrimSpace(event.EventType),
		Severity:         strings.TrimSpace(event.Severity),
		ConfidenceBefore: confidenceBefore,
		ConfidenceAfter:  confidenceAfter,
		CreatedAt:        now,
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO runtime_finding_enrichments (
			id, tenant_id, finding_id, telemetry_event_id, event_type, severity,
			confidence_before, confidence_after, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9
		)
	`, enrichment.ID, enrichment.TenantID, enrichment.FindingID, enrichment.TelemetryEventID, enrichment.EventType, enrichment.Severity,
		enrichment.ConfidenceBefore, enrichment.ConfidenceAfter, enrichment.CreatedAt)
	if err != nil {
		return false, fmt.Errorf("insert runtime finding enrichment: %w", err)
	}

	return true, nil
}

func scanRuntimeFindingEnrichment(row interface{ Scan(dest ...any) error }) (models.RuntimeFindingEnrichment, error) {
	var item models.RuntimeFindingEnrichment
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.FindingID,
		&item.TelemetryEventID,
		&item.EventType,
		&item.Severity,
		&item.ConfidenceBefore,
		&item.ConfidenceAfter,
		&item.CreatedAt,
	)
	if err != nil {
		return models.RuntimeFindingEnrichment{}, err
	}
	return item, nil
}

func appendCanonicalTag(existing []string, next string) []string {
	next = strings.ToLower(strings.TrimSpace(next))
	if next == "" {
		return existing
	}
	for _, value := range existing {
		if strings.ToLower(strings.TrimSpace(value)) == next {
			return existing
		}
	}
	return append(existing, next)
}

func normalizeRuntimeEventTag(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	replacer := strings.NewReplacer(" ", "_", ".", "_", "/", "_", ":", "_")
	value = replacer.Replace(value)
	return value
}

func canonicalEvidenceContains(items []models.CanonicalEvidence, kind string, reference string) bool {
	kind = strings.ToLower(strings.TrimSpace(kind))
	reference = strings.TrimSpace(reference)
	for _, item := range items {
		if strings.ToLower(strings.TrimSpace(item.Kind)) == kind && strings.TrimSpace(item.Ref) == reference {
			return true
		}
	}
	return false
}

func buildRuntimeConfirmationNote(event models.RuntimeTelemetryEvent) string {
	eventType := strings.TrimSpace(event.EventType)
	source := strings.TrimSpace(event.SourceKind)
	if eventType == "" && source == "" {
		return ""
	}
	parts := []string{"Runtime confirmation recorded"}
	if eventType != "" {
		parts = append(parts, "event="+eventType)
	}
	if source != "" {
		parts = append(parts, "source="+source)
	}
	if strings.TrimSpace(event.SourceRef) != "" {
		parts = append(parts, "ref="+strings.TrimSpace(event.SourceRef))
	}
	if !event.ObservedAt.IsZero() {
		parts = append(parts, "observed_at="+event.ObservedAt.UTC().Format(time.RFC3339))
	}
	return strings.Join(parts, " | ")
}

func nextRuntimeFindingEnrichmentID() string {
	value := atomic.AddUint64(&runtimeFindingEnrichmentSequence, 1)
	return fmt.Sprintf("runtime-enrichment-%d-%06d", time.Now().UTC().Unix(), value)
}
