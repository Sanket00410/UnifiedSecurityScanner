package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListDesignReviewsForTenant(ctx context.Context, tenantID string, status string, limit int) ([]models.DesignReview, error) {
	tenantID = strings.TrimSpace(tenantID)
	status = normalizeDesignReviewStatus(status)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, title, service_name, service_id, status,
		       threat_template, summary, diagram_ref, data_classification,
		       design_owner, reviewer, created_by, updated_by,
		       submitted_at, approved_at, closed_at, created_at, updated_at
		FROM design_reviews
		WHERE tenant_id = $1
		  AND ($2 = '' OR status = $2)
		ORDER BY updated_at DESC, id DESC
		LIMIT $3
	`, tenantID, status, limit)
	if err != nil {
		return nil, fmt.Errorf("list design reviews: %w", err)
	}
	defer rows.Close()

	items := make([]models.DesignReview, 0, limit)
	for rows.Next() {
		item, err := scanDesignReview(rows)
		if err != nil {
			return nil, fmt.Errorf("scan design review row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate design review rows: %w", err)
	}

	return items, nil
}

func (s *Store) GetDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string) (models.DesignReview, bool, error) {
	return getDesignReviewTx(ctx, s.pool, tenantID, reviewID)
}

func (s *Store) CreateDesignReviewForTenant(ctx context.Context, tenantID string, actor string, request models.CreateDesignReviewRequest) (models.DesignReview, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	title := strings.TrimSpace(request.Title)
	if title == "" {
		return models.DesignReview{}, fmt.Errorf("title is required")
	}

	now := time.Now().UTC()
	item := models.DesignReview{
		ID:                 nextDesignReviewID(),
		TenantID:           tenantID,
		Title:              title,
		ServiceName:        strings.TrimSpace(request.ServiceName),
		ServiceID:          strings.TrimSpace(request.ServiceID),
		Status:             "draft",
		ThreatTemplate:     strings.TrimSpace(request.ThreatTemplate),
		Summary:            strings.TrimSpace(request.Summary),
		DiagramRef:         strings.TrimSpace(request.DiagramRef),
		DataClassification: strings.TrimSpace(request.DataClassification),
		DesignOwner:        strings.TrimSpace(request.DesignOwner),
		Reviewer:           strings.TrimSpace(request.Reviewer),
		CreatedBy:          actor,
		UpdatedBy:          actor,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO design_reviews (
			id, tenant_id, title, service_name, service_id, status,
			threat_template, summary, diagram_ref, data_classification,
			design_owner, reviewer, created_by, updated_by,
			submitted_at, approved_at, closed_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14,
			NULL, NULL, NULL, $15, $15
		)
		RETURNING id, tenant_id, title, service_name, service_id, status,
		          threat_template, summary, diagram_ref, data_classification,
		          design_owner, reviewer, created_by, updated_by,
		          submitted_at, approved_at, closed_at, created_at, updated_at
	`, item.ID, item.TenantID, item.Title, item.ServiceName, item.ServiceID, item.Status,
		item.ThreatTemplate, item.Summary, item.DiagramRef, item.DataClassification,
		item.DesignOwner, item.Reviewer, item.CreatedBy, item.UpdatedBy, item.CreatedAt)

	created, err := scanDesignReview(row)
	if err != nil {
		return models.DesignReview{}, fmt.Errorf("create design review: %w", err)
	}
	return created, nil
}

func (s *Store) UpdateDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string, actor string, request models.UpdateDesignReviewRequest) (models.DesignReview, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	current, found, err := s.GetDesignReviewForTenant(ctx, tenantID, reviewID)
	if err != nil || !found {
		return models.DesignReview{}, found, err
	}
	if current.Status == "closed" {
		return models.DesignReview{}, true, fmt.Errorf("closed design review cannot be updated")
	}

	if value := strings.TrimSpace(request.Title); value != "" {
		current.Title = value
	}
	if value := strings.TrimSpace(request.ServiceName); value != "" {
		current.ServiceName = value
	}
	if value := strings.TrimSpace(request.ServiceID); value != "" {
		current.ServiceID = value
	}
	if value := strings.TrimSpace(request.ThreatTemplate); value != "" {
		current.ThreatTemplate = value
	}
	if value := strings.TrimSpace(request.Summary); value != "" {
		current.Summary = value
	}
	if value := strings.TrimSpace(request.DiagramRef); value != "" {
		current.DiagramRef = value
	}
	if value := strings.TrimSpace(request.DataClassification); value != "" {
		current.DataClassification = value
	}
	if value := strings.TrimSpace(request.DesignOwner); value != "" {
		current.DesignOwner = value
	}
	if value := strings.TrimSpace(request.Reviewer); value != "" {
		current.Reviewer = value
	}

	current.UpdatedBy = actor
	current.UpdatedAt = time.Now().UTC()

	row := s.pool.QueryRow(ctx, `
		UPDATE design_reviews
		SET title = $3,
		    service_name = $4,
		    service_id = $5,
		    threat_template = $6,
		    summary = $7,
		    diagram_ref = $8,
		    data_classification = $9,
		    design_owner = $10,
		    reviewer = $11,
		    updated_by = $12,
		    updated_at = $13
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, title, service_name, service_id, status,
		          threat_template, summary, diagram_ref, data_classification,
		          design_owner, reviewer, created_by, updated_by,
		          submitted_at, approved_at, closed_at, created_at, updated_at
	`, tenantID, reviewID, current.Title, current.ServiceName, current.ServiceID, current.ThreatTemplate,
		current.Summary, current.DiagramRef, current.DataClassification, current.DesignOwner, current.Reviewer,
		current.UpdatedBy, current.UpdatedAt)

	updated, err := scanDesignReview(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DesignReview{}, false, nil
		}
		return models.DesignReview{}, true, fmt.Errorf("update design review: %w", err)
	}
	return updated, true, nil
}

func (s *Store) SubmitDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string, actor string, _ string) (models.DesignReview, bool, error) {
	return s.transitionDesignReviewForTenant(ctx, tenantID, reviewID, actor, "in_review")
}

func (s *Store) ApproveDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string, actor string, _ string) (models.DesignReview, bool, error) {
	return s.transitionDesignReviewForTenant(ctx, tenantID, reviewID, actor, "approved")
}

func (s *Store) CloseDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string, actor string, _ string) (models.DesignReview, bool, error) {
	return s.transitionDesignReviewForTenant(ctx, tenantID, reviewID, actor, "closed")
}

func (s *Store) transitionDesignReviewForTenant(ctx context.Context, tenantID string, reviewID string, actor string, nextStatus string) (models.DesignReview, bool, error) {
	current, found, err := s.GetDesignReviewForTenant(ctx, tenantID, reviewID)
	if err != nil || !found {
		return models.DesignReview{}, found, err
	}

	currentStatus := normalizeDesignReviewStatus(current.Status)
	if currentStatus == "" {
		currentStatus = "draft"
	}
	if currentStatus == nextStatus {
		return current, true, nil
	}
	if currentStatus == "closed" {
		return models.DesignReview{}, true, fmt.Errorf("closed design review cannot transition to %s", nextStatus)
	}
	if nextStatus == "approved" && currentStatus != "in_review" {
		return models.DesignReview{}, true, fmt.Errorf("design review must be in_review before approval")
	}
	if nextStatus == "closed" && currentStatus != "approved" && currentStatus != "in_review" {
		return models.DesignReview{}, true, fmt.Errorf("design review must be in_review or approved before closure")
	}

	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	now := time.Now().UTC()

	row := s.pool.QueryRow(ctx, `
		UPDATE design_reviews
		SET status = $3,
		    submitted_at = CASE
		        WHEN $3 = 'in_review' AND submitted_at IS NULL THEN $4
		        ELSE submitted_at
		    END,
		    approved_at = CASE
		        WHEN $3 = 'approved' THEN $4
		        ELSE approved_at
		    END,
		    closed_at = CASE
		        WHEN $3 = 'closed' THEN $4
		        ELSE closed_at
		    END,
		    updated_by = $5,
		    updated_at = $4
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, title, service_name, service_id, status,
		          threat_template, summary, diagram_ref, data_classification,
		          design_owner, reviewer, created_by, updated_by,
		          submitted_at, approved_at, closed_at, created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(reviewID), nextStatus, now, actor)

	updated, err := scanDesignReview(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DesignReview{}, false, nil
		}
		return models.DesignReview{}, true, fmt.Errorf("transition design review: %w", err)
	}
	return updated, true, nil
}

func (s *Store) ListDesignThreatsForTenant(ctx context.Context, tenantID string, reviewID string, status string, limit int) ([]models.DesignThreat, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	status = normalizeDesignThreatStatus(status)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, review_id, category, title, description,
		       abuse_case, impact, likelihood, severity, status,
		       linked_asset_id, linked_finding_id, runtime_evidence_refs_json, mitigation,
		       created_by, updated_by, created_at, updated_at
		FROM design_review_threats
		WHERE tenant_id = $1
		  AND review_id = $2
		  AND ($3 = '' OR status = $3)
		ORDER BY updated_at DESC, id DESC
		LIMIT $4
	`, tenantID, reviewID, status, limit)
	if err != nil {
		return nil, fmt.Errorf("list design threats: %w", err)
	}
	defer rows.Close()

	items := make([]models.DesignThreat, 0, limit)
	for rows.Next() {
		item, err := scanDesignThreat(rows)
		if err != nil {
			return nil, fmt.Errorf("scan design threat row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate design threat rows: %w", err)
	}
	return items, nil
}

func (s *Store) CreateDesignThreatForTenant(ctx context.Context, tenantID string, reviewID string, actor string, request models.CreateDesignThreatRequest) (models.DesignThreat, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	title := strings.TrimSpace(request.Title)
	if title == "" {
		return models.DesignThreat{}, fmt.Errorf("title is required")
	}

	now := time.Now().UTC()
	item := models.DesignThreat{
		ID:                  nextDesignThreatID(),
		TenantID:            tenantID,
		ReviewID:            reviewID,
		Category:            strings.TrimSpace(request.Category),
		Title:               title,
		Description:         strings.TrimSpace(request.Description),
		AbuseCase:           strings.TrimSpace(request.AbuseCase),
		Impact:              strings.TrimSpace(request.Impact),
		Likelihood:          strings.TrimSpace(request.Likelihood),
		Severity:            normalizeDesignThreatSeverity(request.Severity),
		Status:              normalizeDesignThreatStatus(request.Status),
		LinkedAssetID:       strings.TrimSpace(request.LinkedAssetID),
		LinkedFindingID:     strings.TrimSpace(request.LinkedFindingID),
		RuntimeEvidenceRefs: sanitizeDesignStringList(request.RuntimeEvidenceRefs),
		Mitigation:          strings.TrimSpace(request.Mitigation),
		CreatedBy:           actor,
		UpdatedBy:           actor,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if item.Status == "" {
		item.Status = "open"
	}
	if item.Severity == "" {
		item.Severity = "medium"
	}

	evidenceJSON, err := json.Marshal(item.RuntimeEvidenceRefs)
	if err != nil {
		return models.DesignThreat{}, fmt.Errorf("marshal design threat evidence refs: %w", err)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.DesignThreat{}, fmt.Errorf("begin design threat create tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, found, err := getDesignReviewTx(ctx, tx, tenantID, reviewID)
	if err != nil {
		return models.DesignThreat{}, err
	}
	if !found {
		return models.DesignThreat{}, ErrDesignReviewNotFound
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO design_review_threats (
			id, tenant_id, review_id, category, title, description,
			abuse_case, impact, likelihood, severity, status,
			linked_asset_id, linked_finding_id, runtime_evidence_refs_json, mitigation,
			created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14, $15,
			$16, $16, $17, $17
		)
		RETURNING id, tenant_id, review_id, category, title, description,
		          abuse_case, impact, likelihood, severity, status,
		          linked_asset_id, linked_finding_id, runtime_evidence_refs_json, mitigation,
		          created_by, updated_by, created_at, updated_at
	`, item.ID, item.TenantID, item.ReviewID, item.Category, item.Title, item.Description,
		item.AbuseCase, item.Impact, item.Likelihood, item.Severity, item.Status,
		item.LinkedAssetID, item.LinkedFindingID, evidenceJSON, item.Mitigation,
		item.CreatedBy, item.CreatedAt)

	created, err := scanDesignThreat(row)
	if err != nil {
		return models.DesignThreat{}, fmt.Errorf("create design threat: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return models.DesignThreat{}, fmt.Errorf("commit design threat create tx: %w", err)
	}
	return created, nil
}

func (s *Store) UpdateDesignThreatForTenant(ctx context.Context, tenantID string, reviewID string, threatID string, actor string, request models.UpdateDesignThreatRequest) (models.DesignThreat, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	threatID = strings.TrimSpace(threatID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.DesignThreat{}, false, fmt.Errorf("begin design threat update tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	current, found, err := getDesignThreatTxForUpdate(ctx, tx, tenantID, reviewID, threatID)
	if err != nil {
		return models.DesignThreat{}, false, err
	}
	if !found {
		return models.DesignThreat{}, false, nil
	}

	if value := strings.TrimSpace(request.Category); value != "" {
		current.Category = value
	}
	if value := strings.TrimSpace(request.Title); value != "" {
		current.Title = value
	}
	if value := strings.TrimSpace(request.Description); value != "" {
		current.Description = value
	}
	if value := strings.TrimSpace(request.AbuseCase); value != "" {
		current.AbuseCase = value
	}
	if value := strings.TrimSpace(request.Impact); value != "" {
		current.Impact = value
	}
	if value := strings.TrimSpace(request.Likelihood); value != "" {
		current.Likelihood = value
	}
	if value := normalizeDesignThreatSeverity(request.Severity); value != "" {
		current.Severity = value
	}
	if value := normalizeDesignThreatStatus(request.Status); value != "" {
		current.Status = value
	}
	if value := strings.TrimSpace(request.LinkedAssetID); value != "" {
		current.LinkedAssetID = value
	}
	if value := strings.TrimSpace(request.LinkedFindingID); value != "" {
		current.LinkedFindingID = value
	}
	if request.RuntimeEvidenceRefs != nil {
		current.RuntimeEvidenceRefs = sanitizeDesignStringList(request.RuntimeEvidenceRefs)
	}
	if value := strings.TrimSpace(request.Mitigation); value != "" {
		current.Mitigation = value
	}
	current.UpdatedBy = actor
	current.UpdatedAt = time.Now().UTC()

	evidenceJSON, err := json.Marshal(current.RuntimeEvidenceRefs)
	if err != nil {
		return models.DesignThreat{}, false, fmt.Errorf("marshal design threat update evidence refs: %w", err)
	}

	row := tx.QueryRow(ctx, `
		UPDATE design_review_threats
		SET category = $4,
		    title = $5,
		    description = $6,
		    abuse_case = $7,
		    impact = $8,
		    likelihood = $9,
		    severity = $10,
		    status = $11,
		    linked_asset_id = $12,
		    linked_finding_id = $13,
		    runtime_evidence_refs_json = $14,
		    mitigation = $15,
		    updated_by = $16,
		    updated_at = $17
		WHERE tenant_id = $1
		  AND review_id = $2
		  AND id = $3
		RETURNING id, tenant_id, review_id, category, title, description,
		          abuse_case, impact, likelihood, severity, status,
		          linked_asset_id, linked_finding_id, runtime_evidence_refs_json, mitigation,
		          created_by, updated_by, created_at, updated_at
	`, tenantID, reviewID, threatID, current.Category, current.Title, current.Description,
		current.AbuseCase, current.Impact, current.Likelihood, current.Severity, current.Status,
		current.LinkedAssetID, current.LinkedFindingID, evidenceJSON, current.Mitigation,
		current.UpdatedBy, current.UpdatedAt)

	updated, err := scanDesignThreat(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DesignThreat{}, false, nil
		}
		return models.DesignThreat{}, false, fmt.Errorf("update design threat: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.DesignThreat{}, false, fmt.Errorf("commit design threat update tx: %w", err)
	}
	return updated, true, nil
}

func (s *Store) GetDesignDataFlowForTenant(ctx context.Context, tenantID string, reviewID string) (models.DesignDataFlowModel, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, review_id, entities_json, flows_json, trust_boundaries_json,
		       notes, updated_by, created_at, updated_at
		FROM design_review_data_flows
		WHERE tenant_id = $1
		  AND review_id = $2
	`, tenantID, reviewID)

	item, err := scanDesignDataFlow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DesignDataFlowModel{}, false, nil
		}
		return models.DesignDataFlowModel{}, false, fmt.Errorf("get design data flow: %w", err)
	}
	return item, true, nil
}

func (s *Store) UpsertDesignDataFlowForTenant(ctx context.Context, tenantID string, reviewID string, actor string, request models.UpsertDesignDataFlowRequest) (models.DesignDataFlowModel, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.DesignDataFlowModel{}, fmt.Errorf("begin design data flow upsert tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, found, err := getDesignReviewTx(ctx, tx, tenantID, reviewID)
	if err != nil {
		return models.DesignDataFlowModel{}, err
	}
	if !found {
		return models.DesignDataFlowModel{}, ErrDesignReviewNotFound
	}

	now := time.Now().UTC()
	current, found, err := getDesignDataFlowTxForUpdate(ctx, tx, tenantID, reviewID)
	if err != nil {
		return models.DesignDataFlowModel{}, err
	}
	if !found {
		current = models.DesignDataFlowModel{
			ID:              nextDesignDataFlowID(),
			TenantID:        tenantID,
			ReviewID:        reviewID,
			Entities:        []map[string]any{},
			Flows:           []map[string]any{},
			TrustBoundaries: []map[string]any{},
			Notes:           "",
			UpdatedBy:       actor,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
	}

	if request.Entities != nil {
		current.Entities = cloneDesignNodeList(request.Entities)
	}
	if request.Flows != nil {
		current.Flows = cloneDesignNodeList(request.Flows)
	}
	if request.TrustBoundaries != nil {
		current.TrustBoundaries = cloneDesignNodeList(request.TrustBoundaries)
	}
	if value := strings.TrimSpace(request.Notes); value != "" {
		current.Notes = value
	}
	current.UpdatedBy = actor
	current.UpdatedAt = now

	entitiesJSON, err := json.Marshal(current.Entities)
	if err != nil {
		return models.DesignDataFlowModel{}, fmt.Errorf("marshal design data flow entities: %w", err)
	}
	flowsJSON, err := json.Marshal(current.Flows)
	if err != nil {
		return models.DesignDataFlowModel{}, fmt.Errorf("marshal design data flow flows: %w", err)
	}
	boundariesJSON, err := json.Marshal(current.TrustBoundaries)
	if err != nil {
		return models.DesignDataFlowModel{}, fmt.Errorf("marshal design data flow trust boundaries: %w", err)
	}

	var row pgx.Row
	if !found {
		row = tx.QueryRow(ctx, `
			INSERT INTO design_review_data_flows (
				id, tenant_id, review_id, entities_json, flows_json, trust_boundaries_json,
				notes, updated_by, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $9
			)
			RETURNING id, tenant_id, review_id, entities_json, flows_json, trust_boundaries_json,
			          notes, updated_by, created_at, updated_at
		`, current.ID, current.TenantID, current.ReviewID, entitiesJSON, flowsJSON, boundariesJSON,
			current.Notes, current.UpdatedBy, current.CreatedAt)
	} else {
		row = tx.QueryRow(ctx, `
			UPDATE design_review_data_flows
			SET entities_json = $4,
			    flows_json = $5,
			    trust_boundaries_json = $6,
			    notes = $7,
			    updated_by = $8,
			    updated_at = $9
			WHERE tenant_id = $1
			  AND review_id = $2
			  AND id = $3
			RETURNING id, tenant_id, review_id, entities_json, flows_json, trust_boundaries_json,
			          notes, updated_by, created_at, updated_at
		`, current.TenantID, current.ReviewID, current.ID, entitiesJSON, flowsJSON, boundariesJSON,
			current.Notes, current.UpdatedBy, current.UpdatedAt)
	}

	updated, err := scanDesignDataFlow(row)
	if err != nil {
		return models.DesignDataFlowModel{}, fmt.Errorf("upsert design data flow: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return models.DesignDataFlowModel{}, fmt.Errorf("commit design data flow upsert tx: %w", err)
	}
	return updated, nil
}

func (s *Store) ListDesignControlMappingsForTenant(ctx context.Context, tenantID string, reviewID string, framework string, limit int) ([]models.DesignControlMapping, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	framework = strings.ToLower(strings.TrimSpace(framework))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, review_id, threat_id, framework, control_id, control_title,
		       status, evidence_ref, notes, created_by, updated_by, created_at, updated_at
		FROM design_control_mappings
		WHERE tenant_id = $1
		  AND review_id = $2
		  AND ($3 = '' OR framework = $3)
		ORDER BY updated_at DESC, id DESC
		LIMIT $4
	`, tenantID, reviewID, framework, limit)
	if err != nil {
		return nil, fmt.Errorf("list design control mappings: %w", err)
	}
	defer rows.Close()

	items := make([]models.DesignControlMapping, 0, limit)
	for rows.Next() {
		item, err := scanDesignControlMapping(rows)
		if err != nil {
			return nil, fmt.Errorf("scan design control mapping row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate design control mapping rows: %w", err)
	}
	return items, nil
}

func (s *Store) CreateDesignControlMappingForTenant(ctx context.Context, tenantID string, reviewID string, actor string, request models.CreateDesignControlMappingRequest) (models.DesignControlMapping, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	framework := strings.ToLower(strings.TrimSpace(request.Framework))
	controlID := strings.TrimSpace(request.ControlID)
	if framework == "" || controlID == "" {
		return models.DesignControlMapping{}, fmt.Errorf("framework and control_id are required")
	}

	now := time.Now().UTC()
	item := models.DesignControlMapping{
		ID:           nextDesignControlMappingID(),
		TenantID:     tenantID,
		ReviewID:     reviewID,
		ThreatID:     strings.TrimSpace(request.ThreatID),
		Framework:    framework,
		ControlID:    controlID,
		ControlTitle: strings.TrimSpace(request.ControlTitle),
		Status:       normalizeDesignControlStatus(request.Status),
		EvidenceRef:  strings.TrimSpace(request.EvidenceRef),
		Notes:        strings.TrimSpace(request.Notes),
		CreatedBy:    actor,
		UpdatedBy:    actor,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if item.Status == "" {
		item.Status = "planned"
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.DesignControlMapping{}, fmt.Errorf("begin design control mapping create tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, found, err := getDesignReviewTx(ctx, tx, tenantID, reviewID)
	if err != nil {
		return models.DesignControlMapping{}, err
	}
	if !found {
		return models.DesignControlMapping{}, ErrDesignReviewNotFound
	}
	if item.ThreatID != "" {
		_, found, err = getDesignThreatTx(ctx, tx, tenantID, reviewID, item.ThreatID)
		if err != nil {
			return models.DesignControlMapping{}, err
		}
		if !found {
			return models.DesignControlMapping{}, ErrDesignThreatNotFound
		}
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO design_control_mappings (
			id, tenant_id, review_id, threat_id, framework, control_id, control_title,
			status, evidence_ref, notes, created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $11, $12, $12
		)
		RETURNING id, tenant_id, review_id, threat_id, framework, control_id, control_title,
		          status, evidence_ref, notes, created_by, updated_by, created_at, updated_at
	`, item.ID, item.TenantID, item.ReviewID, item.ThreatID, item.Framework, item.ControlID, item.ControlTitle,
		item.Status, item.EvidenceRef, item.Notes, item.CreatedBy, item.CreatedAt)

	created, err := scanDesignControlMapping(row)
	if err != nil {
		return models.DesignControlMapping{}, fmt.Errorf("create design control mapping: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return models.DesignControlMapping{}, fmt.Errorf("commit design control mapping create tx: %w", err)
	}
	return created, nil
}

func (s *Store) UpdateDesignControlMappingForTenant(ctx context.Context, tenantID string, reviewID string, mappingID string, actor string, request models.UpdateDesignControlMappingRequest) (models.DesignControlMapping, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	mappingID = strings.TrimSpace(mappingID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.DesignControlMapping{}, false, fmt.Errorf("begin design control mapping update tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	current, found, err := getDesignControlMappingTxForUpdate(ctx, tx, tenantID, reviewID, mappingID)
	if err != nil {
		return models.DesignControlMapping{}, false, err
	}
	if !found {
		return models.DesignControlMapping{}, false, nil
	}

	if value := strings.TrimSpace(request.ThreatID); value != "" {
		_, found, err := getDesignThreatTx(ctx, tx, tenantID, reviewID, value)
		if err != nil {
			return models.DesignControlMapping{}, false, err
		}
		if !found {
			return models.DesignControlMapping{}, false, ErrDesignThreatNotFound
		}
		current.ThreatID = value
	}
	if value := strings.ToLower(strings.TrimSpace(request.Framework)); value != "" {
		current.Framework = value
	}
	if value := strings.TrimSpace(request.ControlID); value != "" {
		current.ControlID = value
	}
	if value := strings.TrimSpace(request.ControlTitle); value != "" {
		current.ControlTitle = value
	}
	if value := normalizeDesignControlStatus(request.Status); value != "" {
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

	row := tx.QueryRow(ctx, `
		UPDATE design_control_mappings
		SET threat_id = $4,
		    framework = $5,
		    control_id = $6,
		    control_title = $7,
		    status = $8,
		    evidence_ref = $9,
		    notes = $10,
		    updated_by = $11,
		    updated_at = $12
		WHERE tenant_id = $1
		  AND review_id = $2
		  AND id = $3
		RETURNING id, tenant_id, review_id, threat_id, framework, control_id, control_title,
		          status, evidence_ref, notes, created_by, updated_by, created_at, updated_at
	`, tenantID, reviewID, mappingID, current.ThreatID, current.Framework, current.ControlID,
		current.ControlTitle, current.Status, current.EvidenceRef, current.Notes, current.UpdatedBy, current.UpdatedAt)

	updated, err := scanDesignControlMapping(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DesignControlMapping{}, false, nil
		}
		return models.DesignControlMapping{}, false, fmt.Errorf("update design control mapping: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.DesignControlMapping{}, false, fmt.Errorf("commit design control mapping update tx: %w", err)
	}
	return updated, true, nil
}

type designReviewReader interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func getDesignReviewTx(ctx context.Context, reader designReviewReader, tenantID string, reviewID string) (models.DesignReview, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	row := reader.QueryRow(ctx, `
		SELECT id, tenant_id, title, service_name, service_id, status,
		       threat_template, summary, diagram_ref, data_classification,
		       design_owner, reviewer, created_by, updated_by,
		       submitted_at, approved_at, closed_at, created_at, updated_at
		FROM design_reviews
		WHERE tenant_id = $1
		  AND id = $2
	`, tenantID, reviewID)
	item, err := scanDesignReview(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DesignReview{}, false, nil
		}
		return models.DesignReview{}, false, fmt.Errorf("get design review: %w", err)
	}
	return item, true, nil
}

func getDesignThreatTx(ctx context.Context, reader designReviewReader, tenantID string, reviewID string, threatID string) (models.DesignThreat, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	reviewID = strings.TrimSpace(reviewID)
	threatID = strings.TrimSpace(threatID)
	row := reader.QueryRow(ctx, `
		SELECT id, tenant_id, review_id, category, title, description,
		       abuse_case, impact, likelihood, severity, status,
		       linked_asset_id, linked_finding_id, runtime_evidence_refs_json, mitigation,
		       created_by, updated_by, created_at, updated_at
		FROM design_review_threats
		WHERE tenant_id = $1
		  AND review_id = $2
		  AND id = $3
	`, tenantID, reviewID, threatID)
	item, err := scanDesignThreat(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DesignThreat{}, false, nil
		}
		return models.DesignThreat{}, false, fmt.Errorf("get design threat: %w", err)
	}
	return item, true, nil
}

func getDesignThreatTxForUpdate(ctx context.Context, tx pgx.Tx, tenantID string, reviewID string, threatID string) (models.DesignThreat, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT id, tenant_id, review_id, category, title, description,
		       abuse_case, impact, likelihood, severity, status,
		       linked_asset_id, linked_finding_id, runtime_evidence_refs_json, mitigation,
		       created_by, updated_by, created_at, updated_at
		FROM design_review_threats
		WHERE tenant_id = $1
		  AND review_id = $2
		  AND id = $3
		FOR UPDATE
	`, strings.TrimSpace(tenantID), strings.TrimSpace(reviewID), strings.TrimSpace(threatID))
	item, err := scanDesignThreat(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DesignThreat{}, false, nil
		}
		return models.DesignThreat{}, false, fmt.Errorf("get design threat for update: %w", err)
	}
	return item, true, nil
}

func getDesignDataFlowTxForUpdate(ctx context.Context, tx pgx.Tx, tenantID string, reviewID string) (models.DesignDataFlowModel, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT id, tenant_id, review_id, entities_json, flows_json, trust_boundaries_json,
		       notes, updated_by, created_at, updated_at
		FROM design_review_data_flows
		WHERE tenant_id = $1
		  AND review_id = $2
		FOR UPDATE
	`, strings.TrimSpace(tenantID), strings.TrimSpace(reviewID))
	item, err := scanDesignDataFlow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DesignDataFlowModel{}, false, nil
		}
		return models.DesignDataFlowModel{}, false, fmt.Errorf("get design data flow for update: %w", err)
	}
	return item, true, nil
}

func getDesignControlMappingTxForUpdate(ctx context.Context, tx pgx.Tx, tenantID string, reviewID string, mappingID string) (models.DesignControlMapping, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT id, tenant_id, review_id, threat_id, framework, control_id, control_title,
		       status, evidence_ref, notes, created_by, updated_by, created_at, updated_at
		FROM design_control_mappings
		WHERE tenant_id = $1
		  AND review_id = $2
		  AND id = $3
		FOR UPDATE
	`, strings.TrimSpace(tenantID), strings.TrimSpace(reviewID), strings.TrimSpace(mappingID))
	item, err := scanDesignControlMapping(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DesignControlMapping{}, false, nil
		}
		return models.DesignControlMapping{}, false, fmt.Errorf("get design control mapping for update: %w", err)
	}
	return item, true, nil
}

func scanDesignReview(row interface{ Scan(dest ...any) error }) (models.DesignReview, error) {
	var item models.DesignReview
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.Title,
		&item.ServiceName,
		&item.ServiceID,
		&item.Status,
		&item.ThreatTemplate,
		&item.Summary,
		&item.DiagramRef,
		&item.DataClassification,
		&item.DesignOwner,
		&item.Reviewer,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.SubmittedAt,
		&item.ApprovedAt,
		&item.ClosedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.DesignReview{}, err
	}
	item.Status = normalizeDesignReviewStatus(item.Status)
	if item.Status == "" {
		item.Status = "draft"
	}
	return item, nil
}

func scanDesignThreat(row interface{ Scan(dest ...any) error }) (models.DesignThreat, error) {
	var (
		item         models.DesignThreat
		evidenceJSON []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.ReviewID,
		&item.Category,
		&item.Title,
		&item.Description,
		&item.AbuseCase,
		&item.Impact,
		&item.Likelihood,
		&item.Severity,
		&item.Status,
		&item.LinkedAssetID,
		&item.LinkedFindingID,
		&evidenceJSON,
		&item.Mitigation,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.DesignThreat{}, err
	}
	if len(evidenceJSON) > 0 {
		if err := json.Unmarshal(evidenceJSON, &item.RuntimeEvidenceRefs); err != nil {
			return models.DesignThreat{}, fmt.Errorf("decode design threat runtime evidence refs: %w", err)
		}
	}
	item.RuntimeEvidenceRefs = sanitizeDesignStringList(item.RuntimeEvidenceRefs)
	item.Severity = normalizeDesignThreatSeverity(item.Severity)
	if item.Severity == "" {
		item.Severity = "medium"
	}
	item.Status = normalizeDesignThreatStatus(item.Status)
	if item.Status == "" {
		item.Status = "open"
	}
	return item, nil
}

func scanDesignDataFlow(row interface{ Scan(dest ...any) error }) (models.DesignDataFlowModel, error) {
	var (
		item           models.DesignDataFlowModel
		entitiesJSON   []byte
		flowsJSON      []byte
		boundariesJSON []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.ReviewID,
		&entitiesJSON,
		&flowsJSON,
		&boundariesJSON,
		&item.Notes,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.DesignDataFlowModel{}, err
	}
	if len(entitiesJSON) > 0 {
		if err := json.Unmarshal(entitiesJSON, &item.Entities); err != nil {
			return models.DesignDataFlowModel{}, fmt.Errorf("decode design data flow entities: %w", err)
		}
	}
	if len(flowsJSON) > 0 {
		if err := json.Unmarshal(flowsJSON, &item.Flows); err != nil {
			return models.DesignDataFlowModel{}, fmt.Errorf("decode design data flow flows: %w", err)
		}
	}
	if len(boundariesJSON) > 0 {
		if err := json.Unmarshal(boundariesJSON, &item.TrustBoundaries); err != nil {
			return models.DesignDataFlowModel{}, fmt.Errorf("decode design data flow trust boundaries: %w", err)
		}
	}
	if item.Entities == nil {
		item.Entities = []map[string]any{}
	}
	if item.Flows == nil {
		item.Flows = []map[string]any{}
	}
	if item.TrustBoundaries == nil {
		item.TrustBoundaries = []map[string]any{}
	}
	return item, nil
}

func scanDesignControlMapping(row interface{ Scan(dest ...any) error }) (models.DesignControlMapping, error) {
	var item models.DesignControlMapping
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.ReviewID,
		&item.ThreatID,
		&item.Framework,
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
		return models.DesignControlMapping{}, err
	}
	item.Framework = strings.ToLower(strings.TrimSpace(item.Framework))
	item.Status = normalizeDesignControlStatus(item.Status)
	if item.Status == "" {
		item.Status = "planned"
	}
	return item, nil
}

func normalizeDesignReviewStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "draft", "in_review", "approved", "closed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeDesignThreatStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "open", "in_progress", "mitigated", "accepted_risk":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeDesignThreatSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low", "informational", "info":
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "info" {
			return "informational"
		}
		return normalized
	default:
		return ""
	}
}

func normalizeDesignControlStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "planned", "implemented", "verified", "not_applicable":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func sanitizeDesignStringList(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return []string{}
	}
	return out
}

func cloneDesignNodeList(values []map[string]any) []map[string]any {
	if len(values) == 0 {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if value == nil {
			out = append(out, map[string]any{})
			continue
		}
		cloned := make(map[string]any, len(value))
		for key, item := range value {
			cloned[strings.TrimSpace(key)] = item
		}
		out = append(out, cloned)
	}
	return out
}

func nextDesignReviewID() string {
	value := atomic.AddUint64(&designReviewSequence, 1)
	return fmt.Sprintf("design-review-%d-%06d", time.Now().UTC().Unix(), value)
}

func nextDesignThreatID() string {
	value := atomic.AddUint64(&designThreatSequence, 1)
	return fmt.Sprintf("design-threat-%d-%06d", time.Now().UTC().Unix(), value)
}

func nextDesignDataFlowID() string {
	value := atomic.AddUint64(&designDataFlowSequence, 1)
	return fmt.Sprintf("design-dataflow-%d-%06d", time.Now().UTC().Unix(), value)
}

func nextDesignControlMappingID() string {
	value := atomic.AddUint64(&designControlMappingSequence, 1)
	return fmt.Sprintf("design-control-%d-%06d", time.Now().UTC().Unix(), value)
}
