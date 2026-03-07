package jobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListComplianceControlMappingsForTenant(ctx context.Context, tenantID string, framework string, sourceID string, limit int) ([]models.ComplianceControlMapping, error) {
	tenantID = strings.TrimSpace(tenantID)
	framework = normalizeComplianceFramework(framework)
	sourceID = strings.TrimSpace(sourceID)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, source_kind, source_id, finding_id, framework, category,
		       control_id, control_title, status, evidence_ref, notes,
		       created_by, updated_by, created_at, updated_at
		FROM compliance_control_mappings
		WHERE tenant_id = $1
		  AND ($2 = '' OR framework = $2)
		  AND ($3 = '' OR source_id = $3)
		ORDER BY updated_at DESC, id DESC
		LIMIT $4
	`, tenantID, framework, sourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list compliance control mappings: %w", err)
	}
	defer rows.Close()

	items := make([]models.ComplianceControlMapping, 0, limit)
	for rows.Next() {
		item, err := scanComplianceControlMapping(rows)
		if err != nil {
			return nil, fmt.Errorf("scan compliance control mapping row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate compliance control mapping rows: %w", err)
	}
	return items, nil
}

func (s *Store) CreateComplianceControlMappingForTenant(ctx context.Context, tenantID string, actor string, request models.CreateComplianceControlMappingRequest) (models.ComplianceControlMapping, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	sourceKind := normalizeComplianceSourceKind(request.SourceKind)
	sourceID := strings.TrimSpace(request.SourceID)
	framework := normalizeComplianceFramework(request.Framework)
	controlID := strings.TrimSpace(request.ControlID)
	if sourceKind == "" || sourceID == "" || framework == "" || controlID == "" {
		return models.ComplianceControlMapping{}, fmt.Errorf("source_kind, source_id, framework, and control_id are required")
	}

	status := normalizeComplianceStatus(request.Status)
	if status == "" {
		status = "identified"
	}

	now := time.Now().UTC()
	item := models.ComplianceControlMapping{
		ID:           nextComplianceMappingID(),
		TenantID:     tenantID,
		SourceKind:   sourceKind,
		SourceID:     sourceID,
		FindingID:    strings.TrimSpace(request.FindingID),
		Framework:    framework,
		Category:     strings.TrimSpace(request.Category),
		ControlID:    controlID,
		ControlTitle: strings.TrimSpace(request.ControlTitle),
		Status:       status,
		EvidenceRef:  strings.TrimSpace(request.EvidenceRef),
		Notes:        strings.TrimSpace(request.Notes),
		CreatedBy:    actor,
		UpdatedBy:    actor,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO compliance_control_mappings (
			id, tenant_id, source_kind, source_id, finding_id, framework, category,
			control_id, control_title, status, evidence_ref, notes,
			created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12,
			$13, $13, $14, $14
		)
		RETURNING id, tenant_id, source_kind, source_id, finding_id, framework, category,
		          control_id, control_title, status, evidence_ref, notes,
		          created_by, updated_by, created_at, updated_at
	`, item.ID, item.TenantID, item.SourceKind, item.SourceID, item.FindingID, item.Framework, item.Category,
		item.ControlID, item.ControlTitle, item.Status, item.EvidenceRef, item.Notes,
		item.CreatedBy, item.CreatedAt)

	created, err := scanComplianceControlMapping(row)
	if err != nil {
		return models.ComplianceControlMapping{}, fmt.Errorf("create compliance control mapping: %w", err)
	}
	return created, nil
}

func (s *Store) UpdateComplianceControlMappingForTenant(ctx context.Context, tenantID string, mappingID string, actor string, request models.UpdateComplianceControlMappingRequest) (models.ComplianceControlMapping, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	mappingID = strings.TrimSpace(mappingID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, source_kind, source_id, finding_id, framework, category,
		       control_id, control_title, status, evidence_ref, notes,
		       created_by, updated_by, created_at, updated_at
		FROM compliance_control_mappings
		WHERE tenant_id = $1
		  AND id = $2
		FOR UPDATE
	`, tenantID, mappingID)
	current, err := scanComplianceControlMapping(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ComplianceControlMapping{}, false, nil
		}
		return models.ComplianceControlMapping{}, false, fmt.Errorf("load compliance control mapping for update: %w", err)
	}

	if value := normalizeComplianceFramework(request.Framework); value != "" {
		current.Framework = value
	}
	if value := strings.TrimSpace(request.Category); value != "" {
		current.Category = value
	}
	if value := strings.TrimSpace(request.ControlID); value != "" {
		current.ControlID = value
	}
	if value := strings.TrimSpace(request.ControlTitle); value != "" {
		current.ControlTitle = value
	}
	if value := normalizeComplianceStatus(request.Status); value != "" {
		current.Status = value
	}
	if value := strings.TrimSpace(request.EvidenceRef); value != "" {
		current.EvidenceRef = value
	}
	if value := strings.TrimSpace(request.Notes); value != "" {
		current.Notes = value
	}
	current.UpdatedBy = actor
	current.UpdatedAt = time.Now().UTC()

	row = s.pool.QueryRow(ctx, `
		UPDATE compliance_control_mappings
		SET framework = $3,
		    category = $4,
		    control_id = $5,
		    control_title = $6,
		    status = $7,
		    evidence_ref = $8,
		    notes = $9,
		    updated_by = $10,
		    updated_at = $11
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, source_kind, source_id, finding_id, framework, category,
		          control_id, control_title, status, evidence_ref, notes,
		          created_by, updated_by, created_at, updated_at
	`, tenantID, mappingID, current.Framework, current.Category, current.ControlID, current.ControlTitle,
		current.Status, current.EvidenceRef, current.Notes, current.UpdatedBy, current.UpdatedAt)

	updated, err := scanComplianceControlMapping(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ComplianceControlMapping{}, false, nil
		}
		return models.ComplianceControlMapping{}, false, fmt.Errorf("update compliance control mapping: %w", err)
	}
	return updated, true, nil
}

func (s *Store) GetComplianceSummaryForTenant(ctx context.Context, tenantID string) (models.ComplianceSummary, error) {
	tenantID = strings.TrimSpace(tenantID)
	summary := models.ComplianceSummary{
		FrameworkTotals: map[string]int64{},
		StatusTotals:    map[string]int64{},
		FrameworkStatus: map[string]map[string]int64{},
	}

	row := s.pool.QueryRow(ctx, `
		SELECT COUNT(*), MAX(updated_at)
		FROM compliance_control_mappings
		WHERE tenant_id = $1
	`, tenantID)
	if err := row.Scan(&summary.TotalMappings, &summary.LastUpdatedAt); err != nil {
		return models.ComplianceSummary{}, fmt.Errorf("load compliance summary totals: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT framework, status, COUNT(*)
		FROM compliance_control_mappings
		WHERE tenant_id = $1
		GROUP BY framework, status
	`, tenantID)
	if err != nil {
		return models.ComplianceSummary{}, fmt.Errorf("load compliance summary groups: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			framework string
			status    string
			count     int64
		)
		if err := rows.Scan(&framework, &status, &count); err != nil {
			return models.ComplianceSummary{}, fmt.Errorf("scan compliance summary group: %w", err)
		}
		framework = normalizeComplianceFramework(framework)
		status = normalizeComplianceStatus(status)
		if framework == "" || status == "" {
			continue
		}
		summary.FrameworkTotals[framework] += count
		summary.StatusTotals[status] += count
		if _, exists := summary.FrameworkStatus[framework]; !exists {
			summary.FrameworkStatus[framework] = map[string]int64{}
		}
		summary.FrameworkStatus[framework][status] += count
	}
	if err := rows.Err(); err != nil {
		return models.ComplianceSummary{}, fmt.Errorf("iterate compliance summary groups: %w", err)
	}

	return summary, nil
}

func scanComplianceControlMapping(row interface{ Scan(dest ...any) error }) (models.ComplianceControlMapping, error) {
	var item models.ComplianceControlMapping
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.SourceKind,
		&item.SourceID,
		&item.FindingID,
		&item.Framework,
		&item.Category,
		&item.ControlID,
		&item.ControlTitle,
		&item.Status,
		&item.EvidenceRef,
		&item.Notes,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.ComplianceControlMapping{}, err
	}
	item.SourceKind = normalizeComplianceSourceKind(item.SourceKind)
	item.Framework = normalizeComplianceFramework(item.Framework)
	item.Status = normalizeComplianceStatus(item.Status)
	return item, nil
}

func normalizeComplianceSourceKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "finding", "design_threat", "runtime_event", "asset", "policy":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeComplianceFramework(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "owasp_top10", "owasp_api_top10", "asvs", "wstg", "samm", "pci", "soc2", "iso27001", "internal":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeComplianceStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "identified", "planned", "implemented", "verified", "not_applicable":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func nextComplianceMappingID() string {
	value := atomic.AddUint64(&complianceMappingSequence, 1)
	return fmt.Sprintf("compliance-mapping-%d-%06d", time.Now().UTC().Unix(), value)
}
