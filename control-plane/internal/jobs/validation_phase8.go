package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListValidationEngagementsForTenant(ctx context.Context, tenantID string, status string, limit int) ([]models.ValidationEngagement, error) {
	tenantID = strings.TrimSpace(tenantID)
	status = normalizeValidationEngagementStatus(status)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, status, target_kind, target, policy_pack_ref,
		       allowed_tools, requires_manual_approval, notes, requested_by,
		       approved_by, approved_at, activated_by, activated_at,
		       closed_by, closed_at, start_at, end_at, created_at, updated_at
		FROM validation_engagements
		WHERE tenant_id = $1
		  AND ($2 = '' OR status = $2)
		ORDER BY updated_at DESC, id DESC
		LIMIT $3
	`, tenantID, status, limit)
	if err != nil {
		return nil, fmt.Errorf("list validation engagements: %w", err)
	}
	defer rows.Close()

	out := make([]models.ValidationEngagement, 0, limit)
	for rows.Next() {
		item, err := scanValidationEngagement(rows)
		if err != nil {
			return nil, fmt.Errorf("scan validation engagement row: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate validation engagement rows: %w", err)
	}

	return out, nil
}

func (s *Store) GetValidationEngagementForTenant(ctx context.Context, tenantID string, engagementID string) (models.ValidationEngagement, bool, error) {
	item, found, err := getValidationEngagementTx(ctx, s.pool, tenantID, engagementID)
	if err != nil {
		return models.ValidationEngagement{}, false, err
	}
	return item, found, nil
}

func (s *Store) CreateValidationEngagementForTenant(ctx context.Context, tenantID string, actor string, request models.CreateValidationEngagementRequest) (models.ValidationEngagement, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	name := strings.TrimSpace(request.Name)
	if name == "" {
		return models.ValidationEngagement{}, fmt.Errorf("name is required")
	}

	now := time.Now().UTC()
	item := models.ValidationEngagement{
		ID:                     nextValidationEngagementID(),
		TenantID:               tenantID,
		Name:                   name,
		Status:                 "draft",
		TargetKind:             strings.ToLower(strings.TrimSpace(request.TargetKind)),
		Target:                 strings.TrimSpace(request.Target),
		PolicyPackRef:          strings.TrimSpace(request.PolicyPackRef),
		AllowedTools:           sanitizeValidationTools(request.AllowedTools),
		RequiresManualApproval: true,
		Notes:                  strings.TrimSpace(request.Notes),
		RequestedBy:            actor,
		StartAt:                request.StartAt,
		EndAt:                  request.EndAt,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if request.RequiresManualApproval != nil {
		item.RequiresManualApproval = *request.RequiresManualApproval
	}
	if err := validateValidationEngagementWindow(item.StartAt, item.EndAt); err != nil {
		return models.ValidationEngagement{}, err
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO validation_engagements (
			id, tenant_id, name, status, target_kind, target, policy_pack_ref,
			allowed_tools, requires_manual_approval, notes, requested_by,
			approved_by, approved_at, activated_by, activated_at,
			closed_by, closed_at, start_at, end_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11,
			'', NULL, '', NULL,
			'', NULL, $12, $13, $14, $14
		)
		RETURNING id, tenant_id, name, status, target_kind, target, policy_pack_ref,
		          allowed_tools, requires_manual_approval, notes, requested_by,
		          approved_by, approved_at, activated_by, activated_at,
		          closed_by, closed_at, start_at, end_at, created_at, updated_at
	`, item.ID, item.TenantID, item.Name, item.Status, item.TargetKind, item.Target, item.PolicyPackRef,
		item.AllowedTools, item.RequiresManualApproval, item.Notes, item.RequestedBy,
		item.StartAt, item.EndAt, item.CreatedAt)

	created, err := scanValidationEngagement(row)
	if err != nil {
		return models.ValidationEngagement{}, fmt.Errorf("create validation engagement: %w", err)
	}

	return created, nil
}

func (s *Store) UpdateValidationEngagementForTenant(ctx context.Context, tenantID string, engagementID string, _ string, request models.UpdateValidationEngagementRequest) (models.ValidationEngagement, bool, error) {
	current, found, err := s.GetValidationEngagementForTenant(ctx, tenantID, engagementID)
	if err != nil || !found {
		return models.ValidationEngagement{}, found, err
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "closed") {
		return models.ValidationEngagement{}, true, fmt.Errorf("closed validation engagement cannot be updated")
	}

	if value := strings.TrimSpace(request.Name); value != "" {
		current.Name = value
	}
	if value := strings.TrimSpace(request.TargetKind); value != "" {
		current.TargetKind = strings.ToLower(value)
	}
	if value := strings.TrimSpace(request.Target); value != "" {
		current.Target = value
	}
	if value := strings.TrimSpace(request.PolicyPackRef); value != "" {
		current.PolicyPackRef = value
	}
	if request.AllowedTools != nil {
		current.AllowedTools = sanitizeValidationTools(request.AllowedTools)
	}
	if request.RequiresManualApproval != nil {
		current.RequiresManualApproval = *request.RequiresManualApproval
	}
	if value := strings.TrimSpace(request.Notes); value != "" {
		current.Notes = value
	}
	if request.StartAt != nil {
		current.StartAt = request.StartAt
	}
	if request.EndAt != nil {
		current.EndAt = request.EndAt
	}
	if err := validateValidationEngagementWindow(current.StartAt, current.EndAt); err != nil {
		return models.ValidationEngagement{}, true, err
	}
	current.UpdatedAt = time.Now().UTC()

	row := s.pool.QueryRow(ctx, `
		UPDATE validation_engagements
		SET name = $3,
		    target_kind = $4,
		    target = $5,
		    policy_pack_ref = $6,
		    allowed_tools = $7,
		    requires_manual_approval = $8,
		    notes = $9,
		    start_at = $10,
		    end_at = $11,
		    updated_at = $12
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, name, status, target_kind, target, policy_pack_ref,
		          allowed_tools, requires_manual_approval, notes, requested_by,
		          approved_by, approved_at, activated_by, activated_at,
		          closed_by, closed_at, start_at, end_at, created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(engagementID), current.Name, current.TargetKind, current.Target, current.PolicyPackRef,
		current.AllowedTools, current.RequiresManualApproval, current.Notes, current.StartAt, current.EndAt, current.UpdatedAt)

	updated, err := scanValidationEngagement(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationEngagement{}, false, nil
		}
		return models.ValidationEngagement{}, true, fmt.Errorf("update validation engagement: %w", err)
	}

	return updated, true, nil
}

func (s *Store) ApproveValidationEngagementForTenant(ctx context.Context, tenantID string, engagementID string, actor string, _ string) (models.ValidationEngagement, bool, error) {
	current, found, err := s.GetValidationEngagementForTenant(ctx, tenantID, engagementID)
	if err != nil || !found {
		return models.ValidationEngagement{}, found, err
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "closed") {
		return models.ValidationEngagement{}, true, fmt.Errorf("closed validation engagement cannot be approved")
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "approved") || strings.EqualFold(strings.TrimSpace(current.Status), "active") {
		return current, true, nil
	}

	now := time.Now().UTC()
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE validation_engagements
		SET status = 'approved',
		    approved_by = $3,
		    approved_at = $4,
		    updated_at = $4
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, name, status, target_kind, target, policy_pack_ref,
		          allowed_tools, requires_manual_approval, notes, requested_by,
		          approved_by, approved_at, activated_by, activated_at,
		          closed_by, closed_at, start_at, end_at, created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(engagementID), actor, now)

	updated, err := scanValidationEngagement(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationEngagement{}, false, nil
		}
		return models.ValidationEngagement{}, true, fmt.Errorf("approve validation engagement: %w", err)
	}
	return updated, true, nil
}

func (s *Store) ActivateValidationEngagementForTenant(ctx context.Context, tenantID string, engagementID string, actor string) (models.ValidationEngagement, bool, error) {
	current, found, err := s.GetValidationEngagementForTenant(ctx, tenantID, engagementID)
	if err != nil || !found {
		return models.ValidationEngagement{}, found, err
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "closed") {
		return models.ValidationEngagement{}, true, fmt.Errorf("closed validation engagement cannot be activated")
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "active") {
		return current, true, nil
	}
	if current.RequiresManualApproval && !strings.EqualFold(strings.TrimSpace(current.Status), "approved") {
		return models.ValidationEngagement{}, true, fmt.Errorf("validation engagement requires approval before activation")
	}
	now := time.Now().UTC()
	if current.StartAt == nil {
		startAt := now
		current.StartAt = &startAt
	}
	if current.EndAt != nil && current.EndAt.Before(now) {
		return models.ValidationEngagement{}, true, fmt.Errorf("validation engagement end_at is in the past")
	}

	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE validation_engagements
		SET status = 'active',
		    activated_by = $3,
		    activated_at = $4,
		    start_at = COALESCE(start_at, $4),
		    updated_at = $4
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, name, status, target_kind, target, policy_pack_ref,
		          allowed_tools, requires_manual_approval, notes, requested_by,
		          approved_by, approved_at, activated_by, activated_at,
		          closed_by, closed_at, start_at, end_at, created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(engagementID), actor, now)

	updated, err := scanValidationEngagement(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationEngagement{}, false, nil
		}
		return models.ValidationEngagement{}, true, fmt.Errorf("activate validation engagement: %w", err)
	}
	return updated, true, nil
}

func (s *Store) CloseValidationEngagementForTenant(ctx context.Context, tenantID string, engagementID string, actor string, _ string) (models.ValidationEngagement, bool, error) {
	current, found, err := s.GetValidationEngagementForTenant(ctx, tenantID, engagementID)
	if err != nil || !found {
		return models.ValidationEngagement{}, found, err
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "closed") {
		return current, true, nil
	}

	now := time.Now().UTC()
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE validation_engagements
		SET status = 'closed',
		    closed_by = $3,
		    closed_at = $4,
		    updated_at = $4
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, name, status, target_kind, target, policy_pack_ref,
		          allowed_tools, requires_manual_approval, notes, requested_by,
		          approved_by, approved_at, activated_by, activated_at,
		          closed_by, closed_at, start_at, end_at, created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(engagementID), actor, now)

	updated, err := scanValidationEngagement(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationEngagement{}, false, nil
		}
		return models.ValidationEngagement{}, true, fmt.Errorf("close validation engagement: %w", err)
	}
	return updated, true, nil
}

type validationEngagementContext struct {
	Engagement models.ValidationEngagement
	Labels     map[string]string
}

func resolveValidationEngagementContextTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	targetKind string,
	target string,
	tools []string,
	taskLabels map[string]string,
	now time.Time,
) (*validationEngagementContext, error) {
	requiredTools := make([]string, 0, len(tools))
	for _, tool := range tools {
		normalized := strings.ToLower(strings.TrimSpace(tool))
		if normalized == "" || !requiresValidationEngagementForTool(normalized) {
			continue
		}
		requiredTools = append(requiredTools, normalized)
	}

	engagementID := ""
	if taskLabels != nil {
		engagementID = strings.TrimSpace(taskLabels["validation_engagement_id"])
	}

	if len(requiredTools) == 0 && engagementID == "" {
		return nil, nil
	}
	if engagementID == "" {
		return nil, ErrValidationEngagementRequired
	}

	engagement, found, err := getValidationEngagementTx(ctx, tx, tenantID, engagementID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrValidationEngagementNotFound
	}

	if !validationEngagementTargetMatches(engagement, targetKind, target) {
		return nil, ErrValidationEngagementScope
	}
	if len(requiredTools) > 0 {
		if !validationEngagementIsActive(engagement, now) {
			return nil, ErrValidationEngagementInactive
		}
		if !validationEngagementAllowsTools(engagement, requiredTools) {
			return nil, ErrValidationEngagementTool
		}
	}

	workflowLabels, err := resolveValidationWorkflowContextTx(
		ctx,
		tx,
		tenantID,
		engagement,
		requiredTools,
		targetKind,
		target,
		taskLabels,
	)
	if err != nil {
		return nil, err
	}

	labels := validationEngagementLabels(engagement)
	for key, value := range workflowLabels {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		normalizedValue := strings.TrimSpace(value)
		if normalizedKey == "" || normalizedValue == "" {
			continue
		}
		labels[normalizedKey] = normalizedValue
	}

	return &validationEngagementContext{
		Engagement: engagement,
		Labels:     labels,
	}, nil
}

func ensureValidationEngagementForDispatchTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	targetKind string,
	target string,
	adapterID string,
	taskLabels map[string]string,
	now time.Time,
) error {
	if !requiresValidationEngagementForTool(adapterID) {
		return nil
	}

	engagementID := strings.TrimSpace(taskLabels["validation_engagement_id"])
	if engagementID == "" {
		return ErrValidationEngagementRequired
	}

	engagement, found, err := getValidationEngagementTx(ctx, tx, tenantID, engagementID)
	if err != nil {
		return err
	}
	if !found {
		return ErrValidationEngagementNotFound
	}
	if !validationEngagementIsActive(engagement, now) {
		return ErrValidationEngagementInactive
	}
	if !validationEngagementTargetMatches(engagement, targetKind, target) {
		return ErrValidationEngagementScope
	}
	if !validationEngagementAllowsTools(engagement, []string{strings.ToLower(strings.TrimSpace(adapterID))}) {
		return ErrValidationEngagementTool
	}
	if err := ensureValidationWorkflowForDispatchTx(
		ctx,
		tx,
		tenantID,
		engagement,
		targetKind,
		target,
		adapterID,
		taskLabels,
	); err != nil {
		return err
	}

	return nil
}

func getValidationEngagementTx(
	ctx context.Context,
	queryer interface {
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	},
	tenantID string,
	engagementID string,
) (models.ValidationEngagement, bool, error) {
	row := queryer.QueryRow(ctx, `
		SELECT id, tenant_id, name, status, target_kind, target, policy_pack_ref,
		       allowed_tools, requires_manual_approval, notes, requested_by,
		       approved_by, approved_at, activated_by, activated_at,
		       closed_by, closed_at, start_at, end_at, created_at, updated_at
		FROM validation_engagements
		WHERE tenant_id = $1
		  AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(engagementID))

	item, err := scanValidationEngagement(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationEngagement{}, false, nil
		}
		return models.ValidationEngagement{}, false, fmt.Errorf("get validation engagement: %w", err)
	}
	return item, true, nil
}

func scanValidationEngagement(row interface{ Scan(dest ...any) error }) (models.ValidationEngagement, error) {
	var (
		item        models.ValidationEngagement
		approvedAt  sql.NullTime
		activatedAt sql.NullTime
		closedAt    sql.NullTime
		startAt     sql.NullTime
		endAt       sql.NullTime
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.Name,
		&item.Status,
		&item.TargetKind,
		&item.Target,
		&item.PolicyPackRef,
		&item.AllowedTools,
		&item.RequiresManualApproval,
		&item.Notes,
		&item.RequestedBy,
		&item.ApprovedBy,
		&approvedAt,
		&item.ActivatedBy,
		&activatedAt,
		&item.ClosedBy,
		&closedAt,
		&startAt,
		&endAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.ValidationEngagement{}, err
	}

	item.Status = normalizeValidationEngagementStatus(item.Status)
	item.TargetKind = strings.ToLower(strings.TrimSpace(item.TargetKind))
	item.Target = strings.TrimSpace(item.Target)
	item.PolicyPackRef = strings.TrimSpace(item.PolicyPackRef)
	item.AllowedTools = sanitizeValidationTools(item.AllowedTools)
	item.Notes = strings.TrimSpace(item.Notes)
	item.RequestedBy = strings.TrimSpace(item.RequestedBy)
	item.ApprovedBy = strings.TrimSpace(item.ApprovedBy)
	item.ActivatedBy = strings.TrimSpace(item.ActivatedBy)
	item.ClosedBy = strings.TrimSpace(item.ClosedBy)

	if approvedAt.Valid {
		value := approvedAt.Time.UTC()
		item.ApprovedAt = &value
	}
	if activatedAt.Valid {
		value := activatedAt.Time.UTC()
		item.ActivatedAt = &value
	}
	if closedAt.Valid {
		value := closedAt.Time.UTC()
		item.ClosedAt = &value
	}
	if startAt.Valid {
		value := startAt.Time.UTC()
		item.StartAt = &value
	}
	if endAt.Valid {
		value := endAt.Time.UTC()
		item.EndAt = &value
	}
	return item, nil
}

func validationEngagementLabels(item models.ValidationEngagement) map[string]string {
	labels := map[string]string{
		"validation_engagement_id":              strings.TrimSpace(item.ID),
		"validation_engagement_name":            strings.TrimSpace(item.Name),
		"validation_engagement_status":          strings.TrimSpace(item.Status),
		"validation_requires_manual_approval":   fmt.Sprintf("%t", item.RequiresManualApproval),
		"validation_engagement_policy_pack_ref": strings.TrimSpace(item.PolicyPackRef),
		"validation_engagement_allowed_tools":   strings.Join(item.AllowedTools, ","),
	}
	if item.StartAt != nil {
		labels["validation_engagement_start_at"] = item.StartAt.UTC().Format(time.RFC3339)
	}
	if item.EndAt != nil {
		labels["validation_engagement_end_at"] = item.EndAt.UTC().Format(time.RFC3339)
	}
	return labels
}

func validationEngagementIsActive(item models.ValidationEngagement, now time.Time) bool {
	if !strings.EqualFold(strings.TrimSpace(item.Status), "active") {
		return false
	}
	if item.StartAt != nil && now.Before(item.StartAt.UTC()) {
		return false
	}
	if item.EndAt != nil && now.After(item.EndAt.UTC()) {
		return false
	}
	return true
}

func validationEngagementTargetMatches(item models.ValidationEngagement, targetKind string, target string) bool {
	engTargetKind := strings.TrimSpace(item.TargetKind)
	if engTargetKind != "" && !strings.EqualFold(engTargetKind, strings.TrimSpace(targetKind)) {
		return false
	}
	engTarget := strings.TrimSpace(item.Target)
	if engTarget != "" && !strings.EqualFold(engTarget, strings.TrimSpace(target)) {
		return false
	}
	return true
}

func validationEngagementAllowsTools(item models.ValidationEngagement, tools []string) bool {
	if len(item.AllowedTools) == 0 {
		return true
	}
	allowed := make(map[string]struct{}, len(item.AllowedTools))
	for _, tool := range item.AllowedTools {
		allowed[strings.ToLower(strings.TrimSpace(tool))] = struct{}{}
	}
	for _, tool := range tools {
		normalized := strings.ToLower(strings.TrimSpace(tool))
		if normalized == "" {
			continue
		}
		if _, ok := allowed[normalized]; !ok {
			return false
		}
	}
	return true
}

func requiresValidationEngagementForTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "metasploit", "sqlmap":
		return true
	default:
		return executionModeForTool(tool) == models.ExecutionModeRestrictedExploit
	}
}

func sanitizeValidationTools(tools []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(tools))
	for _, tool := range tools {
		normalized := strings.ToLower(strings.TrimSpace(tool))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func normalizeValidationEngagementStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "draft":
		return "draft"
	case "approved":
		return "approved"
	case "active":
		return "active"
	case "closed":
		return "closed"
	case "rejected":
		return "rejected"
	default:
		return ""
	}
}

func validateValidationEngagementWindow(startAt *time.Time, endAt *time.Time) error {
	if startAt == nil || endAt == nil {
		return nil
	}
	if endAt.UTC().Before(startAt.UTC()) {
		return fmt.Errorf("end_at must be greater than or equal to start_at")
	}
	return nil
}

func nextValidationEngagementID() string {
	sequence := atomic.AddUint64(&validationEngagementSequence, 1)
	return fmt.Sprintf("validation-engagement-%d-%06d", time.Now().UTC().Unix(), sequence)
}
