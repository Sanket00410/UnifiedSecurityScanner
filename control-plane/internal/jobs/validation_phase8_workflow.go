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

func (s *Store) GetValidationExecutionEnvelopeForTenant(ctx context.Context, tenantID string, engagementID string) (models.ValidationExecutionEnvelope, bool, error) {
	return getValidationExecutionEnvelopeTx(ctx, s.pool, tenantID, engagementID)
}

func (s *Store) UpsertValidationExecutionEnvelopeForTenant(ctx context.Context, tenantID string, engagementID string, actor string, request models.UpsertValidationExecutionEnvelopeRequest) (models.ValidationExecutionEnvelope, error) {
	tenantID = strings.TrimSpace(tenantID)
	engagementID = strings.TrimSpace(engagementID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	if engagementID == "" {
		return models.ValidationExecutionEnvelope{}, ErrValidationEngagementRequired
	}
	if request.MaxRuntimeSeconds != nil && *request.MaxRuntimeSeconds < 0 {
		return models.ValidationExecutionEnvelope{}, fmt.Errorf("max_runtime_seconds must be greater than or equal to zero")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.ValidationExecutionEnvelope{}, fmt.Errorf("begin validation envelope upsert tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	engagement, found, err := getValidationEngagementTx(ctx, tx, tenantID, engagementID)
	if err != nil {
		return models.ValidationExecutionEnvelope{}, err
	}
	if !found {
		return models.ValidationExecutionEnvelope{}, ErrValidationEngagementNotFound
	}

	current, found, err := getValidationExecutionEnvelopeTx(ctx, tx, tenantID, engagementID)
	if err != nil {
		return models.ValidationExecutionEnvelope{}, err
	}

	now := time.Now().UTC()
	if !found {
		current = models.ValidationExecutionEnvelope{
			ID:                   nextValidationEnvelopeID(),
			TenantID:             tenantID,
			EngagementID:         engagementID,
			Status:               "draft",
			PolicyPackRef:        strings.TrimSpace(engagement.PolicyPackRef),
			AllowedTools:         sanitizeValidationTools(engagement.AllowedTools),
			RequiresStepApproval: false,
			MaxRuntimeSeconds:    0,
			NetworkScope:         "",
			Notes:                "",
			CreatedBy:            actor,
			CreatedAt:            now,
			UpdatedAt:            now,
		}
	}

	if value := strings.TrimSpace(request.PolicyPackRef); value != "" {
		current.PolicyPackRef = value
	}
	if request.AllowedTools != nil {
		current.AllowedTools = sanitizeValidationTools(request.AllowedTools)
	}
	if request.RequiresStepApproval != nil {
		current.RequiresStepApproval = *request.RequiresStepApproval
	}
	if request.MaxRuntimeSeconds != nil {
		current.MaxRuntimeSeconds = *request.MaxRuntimeSeconds
	}
	if value := strings.TrimSpace(request.NetworkScope); value != "" {
		current.NetworkScope = value
	}
	if value := strings.TrimSpace(request.Notes); value != "" {
		current.Notes = value
	}
	current.UpdatedAt = now

	var row pgx.Row
	if !found {
		row = tx.QueryRow(ctx, `
			INSERT INTO validation_execution_envelopes (
				id, tenant_id, engagement_id, status, policy_pack_ref, allowed_tools,
				requires_step_approval, max_runtime_seconds, network_scope, notes,
				created_by, approved_by, approved_at, activated_by, activated_at, closed_by, closed_at,
				created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10,
				$11, '', NULL, '', NULL, '', NULL,
				$12, $12
			)
			RETURNING id, tenant_id, engagement_id, status, policy_pack_ref, allowed_tools,
			          requires_step_approval, max_runtime_seconds, network_scope, notes,
			          created_by, approved_by, approved_at, activated_by, activated_at, closed_by, closed_at,
			          created_at, updated_at
		`, current.ID, current.TenantID, current.EngagementID, current.Status, current.PolicyPackRef, current.AllowedTools,
			current.RequiresStepApproval, current.MaxRuntimeSeconds, current.NetworkScope, current.Notes,
			current.CreatedBy, current.CreatedAt)
	} else {
		row = tx.QueryRow(ctx, `
			UPDATE validation_execution_envelopes
			SET policy_pack_ref = $4,
			    allowed_tools = $5,
			    requires_step_approval = $6,
			    max_runtime_seconds = $7,
			    network_scope = $8,
			    notes = $9,
			    updated_at = $10
			WHERE tenant_id = $1
			  AND engagement_id = $2
			  AND id = $3
			RETURNING id, tenant_id, engagement_id, status, policy_pack_ref, allowed_tools,
			          requires_step_approval, max_runtime_seconds, network_scope, notes,
			          created_by, approved_by, approved_at, activated_by, activated_at, closed_by, closed_at,
			          created_at, updated_at
		`, current.TenantID, current.EngagementID, current.ID, current.PolicyPackRef, current.AllowedTools,
			current.RequiresStepApproval, current.MaxRuntimeSeconds, current.NetworkScope, current.Notes, current.UpdatedAt)
	}

	updated, err := scanValidationExecutionEnvelope(row)
	if err != nil {
		return models.ValidationExecutionEnvelope{}, fmt.Errorf("upsert validation execution envelope: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.ValidationExecutionEnvelope{}, fmt.Errorf("commit validation envelope upsert tx: %w", err)
	}

	return updated, nil
}

func (s *Store) ApproveValidationExecutionEnvelopeForTenant(ctx context.Context, tenantID string, engagementID string, actor string, _ string) (models.ValidationExecutionEnvelope, bool, error) {
	current, found, err := s.GetValidationExecutionEnvelopeForTenant(ctx, tenantID, engagementID)
	if err != nil || !found {
		return models.ValidationExecutionEnvelope{}, found, err
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "closed") {
		return models.ValidationExecutionEnvelope{}, true, fmt.Errorf("closed validation execution envelope cannot be approved")
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "approved") || strings.EqualFold(strings.TrimSpace(current.Status), "active") {
		return current, true, nil
	}

	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	now := time.Now().UTC()
	row := s.pool.QueryRow(ctx, `
		UPDATE validation_execution_envelopes
		SET status = 'approved',
		    approved_by = $3,
		    approved_at = $4,
		    updated_at = $4
		WHERE tenant_id = $1
		  AND engagement_id = $2
		RETURNING id, tenant_id, engagement_id, status, policy_pack_ref, allowed_tools,
		          requires_step_approval, max_runtime_seconds, network_scope, notes,
		          created_by, approved_by, approved_at, activated_by, activated_at, closed_by, closed_at,
		          created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(engagementID), actor, now)

	updated, err := scanValidationExecutionEnvelope(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationExecutionEnvelope{}, false, nil
		}
		return models.ValidationExecutionEnvelope{}, true, fmt.Errorf("approve validation execution envelope: %w", err)
	}
	return updated, true, nil
}

func (s *Store) ActivateValidationExecutionEnvelopeForTenant(ctx context.Context, tenantID string, engagementID string, actor string) (models.ValidationExecutionEnvelope, bool, error) {
	current, found, err := s.GetValidationExecutionEnvelopeForTenant(ctx, tenantID, engagementID)
	if err != nil || !found {
		return models.ValidationExecutionEnvelope{}, found, err
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "closed") {
		return models.ValidationExecutionEnvelope{}, true, fmt.Errorf("closed validation execution envelope cannot be activated")
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "active") {
		return current, true, nil
	}
	if !strings.EqualFold(strings.TrimSpace(current.Status), "approved") {
		return models.ValidationExecutionEnvelope{}, true, fmt.Errorf("validation execution envelope requires approval before activation")
	}

	engagement, found, err := s.GetValidationEngagementForTenant(ctx, tenantID, engagementID)
	if err != nil {
		return models.ValidationExecutionEnvelope{}, true, err
	}
	if !found {
		return models.ValidationExecutionEnvelope{}, true, ErrValidationEngagementNotFound
	}
	if !validationEngagementIsActive(engagement, time.Now().UTC()) {
		return models.ValidationExecutionEnvelope{}, true, ErrValidationEngagementInactive
	}

	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	now := time.Now().UTC()
	row := s.pool.QueryRow(ctx, `
		UPDATE validation_execution_envelopes
		SET status = 'active',
		    activated_by = $3,
		    activated_at = $4,
		    updated_at = $4
		WHERE tenant_id = $1
		  AND engagement_id = $2
		RETURNING id, tenant_id, engagement_id, status, policy_pack_ref, allowed_tools,
		          requires_step_approval, max_runtime_seconds, network_scope, notes,
		          created_by, approved_by, approved_at, activated_by, activated_at, closed_by, closed_at,
		          created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(engagementID), actor, now)

	updated, err := scanValidationExecutionEnvelope(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationExecutionEnvelope{}, false, nil
		}
		return models.ValidationExecutionEnvelope{}, true, fmt.Errorf("activate validation execution envelope: %w", err)
	}
	return updated, true, nil
}

func (s *Store) CloseValidationExecutionEnvelopeForTenant(ctx context.Context, tenantID string, engagementID string, actor string, _ string) (models.ValidationExecutionEnvelope, bool, error) {
	current, found, err := s.GetValidationExecutionEnvelopeForTenant(ctx, tenantID, engagementID)
	if err != nil || !found {
		return models.ValidationExecutionEnvelope{}, found, err
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "closed") {
		return current, true, nil
	}

	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	now := time.Now().UTC()
	row := s.pool.QueryRow(ctx, `
		UPDATE validation_execution_envelopes
		SET status = 'closed',
		    closed_by = $3,
		    closed_at = $4,
		    updated_at = $4
		WHERE tenant_id = $1
		  AND engagement_id = $2
		RETURNING id, tenant_id, engagement_id, status, policy_pack_ref, allowed_tools,
		          requires_step_approval, max_runtime_seconds, network_scope, notes,
		          created_by, approved_by, approved_at, activated_by, activated_at, closed_by, closed_at,
		          created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(engagementID), actor, now)

	updated, err := scanValidationExecutionEnvelope(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationExecutionEnvelope{}, false, nil
		}
		return models.ValidationExecutionEnvelope{}, true, fmt.Errorf("close validation execution envelope: %w", err)
	}
	return updated, true, nil
}

func (s *Store) ListValidationPlanStepsForTenant(ctx context.Context, tenantID string, engagementID string, status string, limit int) ([]models.ValidationPlanStep, error) {
	tenantID = strings.TrimSpace(tenantID)
	engagementID = strings.TrimSpace(engagementID)
	status = normalizeValidationPlanStepStatus(status)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, engagement_id, name, adapter_id, target_kind, target, depends_on,
		       status, requested_by, decided_by, reason, created_at, updated_at, decided_at
		FROM validation_plan_steps
		WHERE tenant_id = $1
		  AND ($2 = '' OR engagement_id = $2)
		  AND ($3 = '' OR status = $3)
		ORDER BY updated_at DESC, id DESC
		LIMIT $4
	`, tenantID, engagementID, status, limit)
	if err != nil {
		return nil, fmt.Errorf("list validation plan steps: %w", err)
	}
	defer rows.Close()

	items := make([]models.ValidationPlanStep, 0, limit)
	for rows.Next() {
		item, err := scanValidationPlanStep(rows)
		if err != nil {
			return nil, fmt.Errorf("scan validation plan step row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate validation plan steps: %w", err)
	}
	return items, nil
}

func (s *Store) CreateValidationPlanStepForTenant(ctx context.Context, tenantID string, actor string, request models.CreateValidationPlanStepRequest) (models.ValidationPlanStep, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	engagementID := strings.TrimSpace(request.EngagementID)
	if engagementID == "" {
		return models.ValidationPlanStep{}, ErrValidationEngagementRequired
	}
	name := strings.TrimSpace(request.Name)
	if name == "" {
		return models.ValidationPlanStep{}, fmt.Errorf("name is required")
	}

	now := time.Now().UTC()
	item := models.ValidationPlanStep{
		ID:           nextValidationPlanStepID(),
		TenantID:     tenantID,
		EngagementID: engagementID,
		Name:         name,
		AdapterID:    strings.ToLower(strings.TrimSpace(request.AdapterID)),
		TargetKind:   strings.ToLower(strings.TrimSpace(request.TargetKind)),
		Target:       strings.TrimSpace(request.Target),
		DependsOn:    sanitizeValidationStringList(request.DependsOn),
		Status:       "pending",
		RequestedBy:  actor,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.ValidationPlanStep{}, fmt.Errorf("begin validation plan step create tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, found, err := getValidationEngagementTx(ctx, tx, tenantID, engagementID)
	if err != nil {
		return models.ValidationPlanStep{}, err
	}
	if !found {
		return models.ValidationPlanStep{}, ErrValidationEngagementNotFound
	}

	for _, dependsOnID := range item.DependsOn {
		dependency, found, err := getValidationPlanStepTx(ctx, tx, tenantID, dependsOnID)
		if err != nil {
			return models.ValidationPlanStep{}, err
		}
		if !found {
			return models.ValidationPlanStep{}, ErrValidationPlanStepNotFound
		}
		if !strings.EqualFold(strings.TrimSpace(dependency.EngagementID), item.EngagementID) {
			return models.ValidationPlanStep{}, ErrValidationPlanStepScope
		}
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO validation_plan_steps (
			id, tenant_id, engagement_id, name, adapter_id, target_kind, target, depends_on,
			status, requested_by, decided_by, reason, created_at, updated_at, decided_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, '', '', $11, $11, NULL
		)
		RETURNING id, tenant_id, engagement_id, name, adapter_id, target_kind, target, depends_on,
		          status, requested_by, decided_by, reason, created_at, updated_at, decided_at
	`, item.ID, item.TenantID, item.EngagementID, item.Name, item.AdapterID, item.TargetKind, item.Target, item.DependsOn,
		item.Status, item.RequestedBy, item.CreatedAt)

	created, err := scanValidationPlanStep(row)
	if err != nil {
		return models.ValidationPlanStep{}, fmt.Errorf("create validation plan step: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.ValidationPlanStep{}, fmt.Errorf("commit validation plan step create tx: %w", err)
	}
	return created, nil
}

func (s *Store) DecideValidationPlanStepForTenant(ctx context.Context, tenantID string, stepID string, approved bool, actor string, reason string) (models.ValidationPlanStep, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	stepID = strings.TrimSpace(stepID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.ValidationPlanStep{}, false, fmt.Errorf("begin validation plan step decision tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	current, found, err := getValidationPlanStepTxForUpdate(ctx, tx, tenantID, stepID)
	if err != nil {
		return models.ValidationPlanStep{}, false, err
	}
	if !found {
		return models.ValidationPlanStep{}, false, nil
	}
	if strings.EqualFold(strings.TrimSpace(current.Status), "approved") || strings.EqualFold(strings.TrimSpace(current.Status), "denied") {
		if err := tx.Commit(ctx); err != nil {
			return models.ValidationPlanStep{}, false, fmt.Errorf("commit unchanged validation plan step decision tx: %w", err)
		}
		return current, true, nil
	}

	now := time.Now().UTC()
	nextStatus := "denied"
	if approved {
		dependenciesApproved, err := validationPlanStepDependenciesApprovedTx(ctx, tx, tenantID, current)
		if err != nil {
			return models.ValidationPlanStep{}, false, err
		}
		if !dependenciesApproved {
			return models.ValidationPlanStep{}, false, ErrValidationPlanStepDependency
		}
		nextStatus = "approved"
	}

	current.Status = nextStatus
	current.DecidedBy = actor
	current.Reason = strings.TrimSpace(reason)
	current.DecidedAt = &now
	current.UpdatedAt = now

	row := tx.QueryRow(ctx, `
		UPDATE validation_plan_steps
		SET status = $3,
		    decided_by = $4,
		    reason = $5,
		    updated_at = $6,
		    decided_at = $7
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, engagement_id, name, adapter_id, target_kind, target, depends_on,
		          status, requested_by, decided_by, reason, created_at, updated_at, decided_at
	`, tenantID, stepID, current.Status, current.DecidedBy, current.Reason, current.UpdatedAt, current.DecidedAt)

	updated, err := scanValidationPlanStep(row)
	if err != nil {
		return models.ValidationPlanStep{}, false, fmt.Errorf("update validation plan step decision: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.ValidationPlanStep{}, false, fmt.Errorf("commit validation plan step decision tx: %w", err)
	}
	return updated, true, nil
}

func getValidationExecutionEnvelopeTx(
	ctx context.Context,
	queryer interface {
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	},
	tenantID string,
	engagementID string,
) (models.ValidationExecutionEnvelope, bool, error) {
	row := queryer.QueryRow(ctx, `
		SELECT id, tenant_id, engagement_id, status, policy_pack_ref, allowed_tools,
		       requires_step_approval, max_runtime_seconds, network_scope, notes,
		       created_by, approved_by, approved_at, activated_by, activated_at, closed_by, closed_at,
		       created_at, updated_at
		FROM validation_execution_envelopes
		WHERE tenant_id = $1
		  AND engagement_id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(engagementID))

	item, err := scanValidationExecutionEnvelope(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationExecutionEnvelope{}, false, nil
		}
		return models.ValidationExecutionEnvelope{}, false, fmt.Errorf("get validation execution envelope: %w", err)
	}
	return item, true, nil
}

func getValidationPlanStepTx(
	ctx context.Context,
	queryer interface {
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	},
	tenantID string,
	stepID string,
) (models.ValidationPlanStep, bool, error) {
	row := queryer.QueryRow(ctx, `
		SELECT id, tenant_id, engagement_id, name, adapter_id, target_kind, target, depends_on,
		       status, requested_by, decided_by, reason, created_at, updated_at, decided_at
		FROM validation_plan_steps
		WHERE tenant_id = $1
		  AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(stepID))

	item, err := scanValidationPlanStep(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationPlanStep{}, false, nil
		}
		return models.ValidationPlanStep{}, false, fmt.Errorf("get validation plan step: %w", err)
	}
	return item, true, nil
}

func getValidationPlanStepTxForUpdate(ctx context.Context, tx pgx.Tx, tenantID string, stepID string) (models.ValidationPlanStep, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT id, tenant_id, engagement_id, name, adapter_id, target_kind, target, depends_on,
		       status, requested_by, decided_by, reason, created_at, updated_at, decided_at
		FROM validation_plan_steps
		WHERE tenant_id = $1
		  AND id = $2
		FOR UPDATE
	`, strings.TrimSpace(tenantID), strings.TrimSpace(stepID))

	item, err := scanValidationPlanStep(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ValidationPlanStep{}, false, nil
		}
		return models.ValidationPlanStep{}, false, fmt.Errorf("get validation plan step for update: %w", err)
	}
	return item, true, nil
}

func scanValidationExecutionEnvelope(row interface{ Scan(dest ...any) error }) (models.ValidationExecutionEnvelope, error) {
	var (
		item        models.ValidationExecutionEnvelope
		approvedAt  sql.NullTime
		activatedAt sql.NullTime
		closedAt    sql.NullTime
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.EngagementID,
		&item.Status,
		&item.PolicyPackRef,
		&item.AllowedTools,
		&item.RequiresStepApproval,
		&item.MaxRuntimeSeconds,
		&item.NetworkScope,
		&item.Notes,
		&item.CreatedBy,
		&item.ApprovedBy,
		&approvedAt,
		&item.ActivatedBy,
		&activatedAt,
		&item.ClosedBy,
		&closedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.ValidationExecutionEnvelope{}, err
	}

	item.Status = normalizeValidationEnvelopeStatus(item.Status)
	item.PolicyPackRef = strings.TrimSpace(item.PolicyPackRef)
	item.AllowedTools = sanitizeValidationTools(item.AllowedTools)
	item.NetworkScope = strings.TrimSpace(item.NetworkScope)
	item.Notes = strings.TrimSpace(item.Notes)
	item.CreatedBy = strings.TrimSpace(item.CreatedBy)
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
	return item, nil
}

func scanValidationPlanStep(row interface{ Scan(dest ...any) error }) (models.ValidationPlanStep, error) {
	var (
		item      models.ValidationPlanStep
		decidedAt sql.NullTime
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.EngagementID,
		&item.Name,
		&item.AdapterID,
		&item.TargetKind,
		&item.Target,
		&item.DependsOn,
		&item.Status,
		&item.RequestedBy,
		&item.DecidedBy,
		&item.Reason,
		&item.CreatedAt,
		&item.UpdatedAt,
		&decidedAt,
	)
	if err != nil {
		return models.ValidationPlanStep{}, err
	}

	item.Name = strings.TrimSpace(item.Name)
	item.AdapterID = strings.ToLower(strings.TrimSpace(item.AdapterID))
	item.TargetKind = strings.ToLower(strings.TrimSpace(item.TargetKind))
	item.Target = strings.TrimSpace(item.Target)
	item.DependsOn = sanitizeValidationStringList(item.DependsOn)
	item.Status = normalizeValidationPlanStepStatus(item.Status)
	item.RequestedBy = strings.TrimSpace(item.RequestedBy)
	item.DecidedBy = strings.TrimSpace(item.DecidedBy)
	item.Reason = strings.TrimSpace(item.Reason)
	if decidedAt.Valid {
		value := decidedAt.Time.UTC()
		item.DecidedAt = &value
	}
	return item, nil
}

func normalizeValidationEnvelopeStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "draft":
		return "draft"
	case "approved":
		return "approved"
	case "active":
		return "active"
	case "closed":
		return "closed"
	default:
		return ""
	}
}

func normalizeValidationPlanStepStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pending":
		return "pending"
	case "approved":
		return "approved"
	case "denied":
		return "denied"
	case "executed":
		return "executed"
	default:
		return ""
	}
}

func validationExecutionEnvelopeIsActive(item models.ValidationExecutionEnvelope) bool {
	return strings.EqualFold(strings.TrimSpace(item.Status), "active")
}

func validationExecutionEnvelopeAllowsTools(item models.ValidationExecutionEnvelope, tools []string) bool {
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

func validationPlanStepDependenciesApprovedTx(ctx context.Context, tx pgx.Tx, tenantID string, step models.ValidationPlanStep) (bool, error) {
	for _, dependencyID := range step.DependsOn {
		dependency, found, err := getValidationPlanStepTx(ctx, tx, tenantID, dependencyID)
		if err != nil {
			return false, err
		}
		if !found {
			return false, ErrValidationPlanStepNotFound
		}
		if !strings.EqualFold(strings.TrimSpace(dependency.EngagementID), strings.TrimSpace(step.EngagementID)) {
			return false, ErrValidationPlanStepScope
		}
		if !strings.EqualFold(strings.TrimSpace(dependency.Status), "approved") && !strings.EqualFold(strings.TrimSpace(dependency.Status), "executed") {
			return false, nil
		}
	}
	return true, nil
}

func validationExecutionEnvelopeLabels(item models.ValidationExecutionEnvelope) map[string]string {
	labels := map[string]string{
		"validation_execution_envelope_id":            strings.TrimSpace(item.ID),
		"validation_execution_envelope_status":        strings.TrimSpace(item.Status),
		"validation_execution_policy_pack_ref":        strings.TrimSpace(item.PolicyPackRef),
		"validation_execution_allowed_tools":          strings.Join(item.AllowedTools, ","),
		"validation_execution_requires_step_approval": fmt.Sprintf("%t", item.RequiresStepApproval),
		"validation_execution_network_scope":          strings.TrimSpace(item.NetworkScope),
	}
	if item.MaxRuntimeSeconds > 0 {
		labels["validation_execution_max_runtime_seconds"] = fmt.Sprintf("%d", item.MaxRuntimeSeconds)
	}
	return labels
}

func validationPlanStepLabels(step models.ValidationPlanStep) map[string]string {
	labels := map[string]string{
		"validation_plan_step_id":      strings.TrimSpace(step.ID),
		"validation_plan_step_name":    strings.TrimSpace(step.Name),
		"validation_plan_step_status":  strings.TrimSpace(step.Status),
		"validation_plan_step_adapter": strings.TrimSpace(step.AdapterID),
	}
	if len(step.DependsOn) > 0 {
		labels["validation_plan_step_depends_on"] = strings.Join(step.DependsOn, ",")
	}
	return labels
}

func resolveValidationWorkflowContextTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	engagement models.ValidationEngagement,
	requiredTools []string,
	targetKind string,
	target string,
	taskLabels map[string]string,
) (map[string]string, error) {
	labels := map[string]string{}
	envelope, envelopeFound, err := getValidationExecutionEnvelopeTx(ctx, tx, tenantID, engagement.ID)
	if err != nil {
		return nil, err
	}
	if envelopeFound {
		for key, value := range validationExecutionEnvelopeLabels(envelope) {
			labels[key] = value
		}
		if len(requiredTools) > 0 {
			if !validationExecutionEnvelopeIsActive(envelope) {
				return nil, ErrValidationEnvelopeInactive
			}
			if !validationExecutionEnvelopeAllowsTools(envelope, requiredTools) {
				return nil, ErrValidationEngagementTool
			}
		}
	}

	stepID := ""
	if taskLabels != nil {
		stepID = strings.TrimSpace(taskLabels["validation_plan_step_id"])
	}
	if envelopeFound && envelope.RequiresStepApproval && len(requiredTools) > 0 && stepID == "" {
		return nil, ErrValidationPlanStepRequired
	}
	if stepID != "" {
		step, found, err := getValidationPlanStepTx(ctx, tx, tenantID, stepID)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, ErrValidationPlanStepNotFound
		}
		if !validationPlanStepMatches(step, engagement, requiredTools, targetKind, target) {
			return nil, ErrValidationPlanStepScope
		}
		if !validationPlanStepIsApproved(step) {
			return nil, ErrValidationPlanStepNotApproved
		}
		dependenciesApproved, err := validationPlanStepDependenciesApprovedTx(ctx, tx, tenantID, step)
		if err != nil {
			return nil, err
		}
		if !dependenciesApproved {
			return nil, ErrValidationPlanStepDependency
		}
		for key, value := range validationPlanStepLabels(step) {
			labels[key] = value
		}
	}
	return labels, nil
}

func ensureValidationWorkflowForDispatchTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	engagement models.ValidationEngagement,
	targetKind string,
	target string,
	adapterID string,
	taskLabels map[string]string,
) error {
	envelope, envelopeFound, err := getValidationExecutionEnvelopeTx(ctx, tx, tenantID, engagement.ID)
	if err != nil {
		return err
	}
	if envelopeFound {
		if !validationExecutionEnvelopeIsActive(envelope) {
			return ErrValidationEnvelopeInactive
		}
		if !validationExecutionEnvelopeAllowsTools(envelope, []string{adapterID}) {
			return ErrValidationEngagementTool
		}
	}

	stepID := strings.TrimSpace(taskLabels["validation_plan_step_id"])
	if envelopeFound && envelope.RequiresStepApproval && stepID == "" {
		return ErrValidationPlanStepRequired
	}
	if stepID != "" {
		step, found, err := getValidationPlanStepTx(ctx, tx, tenantID, stepID)
		if err != nil {
			return err
		}
		if !found {
			return ErrValidationPlanStepNotFound
		}
		if !validationPlanStepMatches(step, engagement, []string{adapterID}, targetKind, target) {
			return ErrValidationPlanStepScope
		}
		if !validationPlanStepIsApproved(step) {
			return ErrValidationPlanStepNotApproved
		}
		dependenciesApproved, err := validationPlanStepDependenciesApprovedTx(ctx, tx, tenantID, step)
		if err != nil {
			return err
		}
		if !dependenciesApproved {
			return ErrValidationPlanStepDependency
		}
	}

	return nil
}

func validationPlanStepMatches(step models.ValidationPlanStep, engagement models.ValidationEngagement, tools []string, targetKind string, target string) bool {
	if !strings.EqualFold(strings.TrimSpace(step.EngagementID), strings.TrimSpace(engagement.ID)) {
		return false
	}
	if value := strings.TrimSpace(step.AdapterID); value != "" {
		matched := false
		for _, tool := range tools {
			if strings.EqualFold(value, strings.TrimSpace(tool)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if value := strings.TrimSpace(step.TargetKind); value != "" && !strings.EqualFold(value, strings.TrimSpace(targetKind)) {
		return false
	}
	if value := strings.TrimSpace(step.Target); value != "" && !strings.EqualFold(value, strings.TrimSpace(target)) {
		return false
	}
	return true
}

func validationPlanStepIsApproved(step models.ValidationPlanStep) bool {
	return strings.EqualFold(strings.TrimSpace(step.Status), "approved") || strings.EqualFold(strings.TrimSpace(step.Status), "executed")
}

func nextValidationEnvelopeID() string {
	sequence := atomic.AddUint64(&validationEnvelopeSequence, 1)
	return fmt.Sprintf("validation-envelope-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextValidationPlanStepID() string {
	sequence := atomic.AddUint64(&validationPlanStepSequence, 1)
	return fmt.Sprintf("validation-plan-step-%d-%06d", time.Now().UTC().Unix(), sequence)
}
