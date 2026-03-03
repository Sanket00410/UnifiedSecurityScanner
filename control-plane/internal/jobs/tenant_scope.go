package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) CreateForTenant(ctx context.Context, organizationID string, request models.CreateScanJobRequest) (models.ScanJob, error) {
	request.TenantID = strings.TrimSpace(organizationID)
	return s.Create(ctx, request)
}

func (s *Store) GetForTenant(ctx context.Context, organizationID string, id string) (models.ScanJob, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, target_kind, target, profile, requested_by,
		       tools, approval_mode, status, requested_at, updated_at
		FROM scan_jobs
		WHERE id = $1 AND tenant_id = $2
	`, strings.TrimSpace(id), strings.TrimSpace(organizationID))

	job, err := scanJobFromRow(row)
	if err != nil {
		if isNoRows(err) {
			return models.ScanJob{}, false, nil
		}
		return models.ScanJob{}, false, fmt.Errorf("select tenant scan job: %w", err)
	}

	return job, true, nil
}

func (s *Store) ListForTenant(ctx context.Context, organizationID string, limit int) ([]models.ScanJob, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, target_kind, target, profile, requested_by,
		       tools, approval_mode, status, requested_at, updated_at
		FROM scan_jobs
		WHERE tenant_id = $1
		ORDER BY requested_at DESC
		LIMIT $2
	`, strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list tenant scan jobs: %w", err)
	}
	defer rows.Close()

	out := make([]models.ScanJob, 0, limit)
	for rows.Next() {
		job, err := scanJobFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant scan jobs: %w", err)
	}

	return out, nil
}

func (s *Store) ListFindingsForTenant(ctx context.Context, organizationID string, limit int) ([]models.CanonicalFinding, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT finding_json
		FROM normalized_findings
		WHERE tenant_id = $1
		ORDER BY COALESCE(NULLIF(finding_json->'risk'->>'overall_score', '')::double precision, 0) DESC,
		         updated_at DESC
		LIMIT $2
	`, strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list tenant findings: %w", err)
	}
	defer rows.Close()

	out := make([]models.CanonicalFinding, 0, limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan tenant finding: %w", err)
		}

		var finding models.CanonicalFinding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return nil, fmt.Errorf("unmarshal tenant finding: %w", err)
		}

		out = append(out, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant findings: %w", err)
	}

	out, err = s.applyEffectiveRiskAdjustments(ctx, strings.TrimSpace(organizationID), out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (s *Store) ListAssetsForTenant(ctx context.Context, organizationID string, limit int) ([]models.AssetSummary, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		WITH tenant_assets AS (
			SELECT target AS asset_id, target_kind AS asset_type
			FROM scan_jobs
			WHERE tenant_id = $1
			UNION
			SELECT asset_id, asset_type
			FROM asset_profiles
			WHERE tenant_id = $1
		)
		SELECT
			ta.asset_id,
			COALESCE(NULLIF(ap.asset_type, ''), ta.asset_type),
			COALESCE(ap.environment, ''),
			COALESCE(ap.exposure, ''),
			COALESCE(ap.criticality, 0),
			COALESCE(ap.owner_team, ''),
			COALESCE(ap.owner_hierarchy_json, '[]'::jsonb),
			COALESCE(ap.service_name, ''),
			COALESCE(ap.service_tier, ''),
			COALESCE(ap.service_criticality_class, ''),
			COALESCE(ap.external_source, ''),
			ap.last_synced_at,
			COALESCE(COUNT(DISTINCT cc.id), 0) AS compensating_control_count,
			COALESCE(MAX(sj.updated_at), ap.updated_at, ap.created_at) AS last_scanned_at,
			COUNT(DISTINCT sj.id) AS scan_count,
			COUNT(DISTINCT nf.finding_id) AS finding_count
		FROM tenant_assets ta
		LEFT JOIN scan_jobs sj ON sj.tenant_id = $1 AND sj.target = ta.asset_id
		LEFT JOIN normalized_findings nf ON nf.tenant_id = $1 AND nf.scan_job_id = sj.id
		LEFT JOIN asset_profiles ap ON ap.tenant_id = $1 AND ap.asset_id = ta.asset_id
		LEFT JOIN compensating_controls cc ON cc.tenant_id = $1 AND cc.asset_id = ta.asset_id AND cc.enabled = TRUE
		GROUP BY ta.asset_id, COALESCE(NULLIF(ap.asset_type, ''), ta.asset_type), ap.environment, ap.exposure, ap.criticality,
		         ap.owner_team, ap.owner_hierarchy_json, ap.service_name, ap.service_tier, ap.service_criticality_class,
		         ap.external_source, ap.last_synced_at, ap.updated_at, ap.created_at
		ORDER BY COALESCE(MAX(sj.updated_at), ap.updated_at, ap.created_at) DESC
		LIMIT $2
	`, strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list tenant assets: %w", err)
	}
	defer rows.Close()

	out := make([]models.AssetSummary, 0, limit)
	for rows.Next() {
		var asset models.AssetSummary
		var ownerHierarchyJSON []byte
		var lastSyncedAt sql.NullTime
		if err := rows.Scan(
			&asset.AssetID,
			&asset.AssetType,
			&asset.Environment,
			&asset.Exposure,
			&asset.Criticality,
			&asset.OwnerTeam,
			&ownerHierarchyJSON,
			&asset.ServiceName,
			&asset.ServiceTier,
			&asset.ServiceCriticalityClass,
			&asset.ExternalSource,
			&lastSyncedAt,
			&asset.CompensatingControlCount,
			&asset.LastScannedAt,
			&asset.ScanCount,
			&asset.FindingCount,
		); err != nil {
			return nil, fmt.Errorf("scan tenant asset: %w", err)
		}
		if len(ownerHierarchyJSON) > 0 {
			if err := json.Unmarshal(ownerHierarchyJSON, &asset.OwnerHierarchy); err != nil {
				return nil, fmt.Errorf("decode tenant asset owner hierarchy: %w", err)
			}
		}
		if lastSyncedAt.Valid {
			value := lastSyncedAt.Time.UTC()
			asset.LastSyncedAt = &value
		}
		out = append(out, asset)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant assets: %w", err)
	}

	return out, nil
}

func (s *Store) ListPoliciesForTenant(ctx context.Context, organizationID string, limit int) ([]models.Policy, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id, id, version_number, name, scope, mode, enabled, rules_json, updated_by, created_at, updated_at
		FROM policies
		WHERE tenant_id = $1 OR tenant_id = ''
		ORDER BY updated_at DESC
		LIMIT $2
	`, strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list tenant policies: %w", err)
	}
	defer rows.Close()

	out := make([]models.Policy, 0, limit)
	for rows.Next() {
		var policy models.Policy
		var rulesJSON []byte

		if err := rows.Scan(
			&policy.TenantID,
			&policy.ID,
			&policy.VersionNumber,
			&policy.Name,
			&policy.Scope,
			&policy.Mode,
			&policy.Enabled,
			&rulesJSON,
			&policy.UpdatedBy,
			&policy.CreatedAt,
			&policy.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan tenant policy: %w", err)
		}
		if len(rulesJSON) > 0 {
			if err := json.Unmarshal(rulesJSON, &policy.Rules); err != nil {
				return nil, fmt.Errorf("unmarshal tenant policy rules: %w", err)
			}
		}

		out = append(out, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant policies: %w", err)
	}

	return out, nil
}

func (s *Store) CreatePolicyForTenant(ctx context.Context, organizationID string, request models.CreatePolicyRequest) (models.Policy, error) {
	now := time.Now().UTC()
	policy := models.Policy{
		ID:            nextPolicyID(),
		TenantID:      strings.TrimSpace(organizationID),
		VersionNumber: 1,
		Name:          strings.TrimSpace(request.Name),
		Scope:         strings.TrimSpace(request.Scope),
		Mode:          strings.TrimSpace(request.Mode),
		Enabled:       request.Enabled,
		Rules:         sanitizeRuleList(request.Rules),
		UpdatedBy:     strings.TrimSpace(request.UpdatedBy),
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if policy.Scope == "" {
		policy.Scope = "tenant"
	}
	if policy.Mode == "" {
		policy.Mode = "monitor"
	}

	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return models.Policy{}, fmt.Errorf("marshal tenant policy rules: %w", err)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.Policy{}, fmt.Errorf("begin tenant policy tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO policies (
			id, tenant_id, version_number, name, scope, mode, enabled, rules_json, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10
		)
	`, policy.ID, policy.TenantID, policy.VersionNumber, policy.Name, policy.Scope, policy.Mode, policy.Enabled, rulesJSON, policy.UpdatedBy, now)
	if err != nil {
		return models.Policy{}, fmt.Errorf("insert tenant policy: %w", err)
	}

	if err := recordPolicyVersionTx(ctx, tx, policy, "created", policy.UpdatedBy); err != nil {
		return models.Policy{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.Policy{}, fmt.Errorf("commit tenant policy tx: %w", err)
	}

	return policy, nil
}

func (s *Store) ListRemediationsForTenant(ctx context.Context, organizationID string, limit int) ([]models.RemediationAction, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id, id, finding_id, title, status, owner, due_at, notes, created_at, updated_at
		FROM remediation_actions
		WHERE tenant_id = $1
		ORDER BY updated_at DESC
		LIMIT $2
	`, strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list tenant remediations: %w", err)
	}
	defer rows.Close()

	out := make([]models.RemediationAction, 0, limit)
	for rows.Next() {
		var item models.RemediationAction
		if err := rows.Scan(
			&item.TenantID,
			&item.ID,
			&item.FindingID,
			&item.Title,
			&item.Status,
			&item.Owner,
			&item.DueAt,
			&item.Notes,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan tenant remediation: %w", err)
		}
		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant remediations: %w", err)
	}

	return out, nil
}

func (s *Store) GetRemediationForTenant(ctx context.Context, organizationID string, remediationID string) (models.RemediationAction, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, id, finding_id, title, status, owner, due_at, notes, created_at, updated_at
		FROM remediation_actions
		WHERE tenant_id = $1
		  AND id = $2
	`, strings.TrimSpace(organizationID), strings.TrimSpace(remediationID))

	var item models.RemediationAction
	err := row.Scan(
		&item.TenantID,
		&item.ID,
		&item.FindingID,
		&item.Title,
		&item.Status,
		&item.Owner,
		&item.DueAt,
		&item.Notes,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.RemediationAction{}, false, nil
		}
		return models.RemediationAction{}, false, fmt.Errorf("get tenant remediation: %w", err)
	}

	return item, true, nil
}

func (s *Store) CreateRemediationForTenant(ctx context.Context, organizationID string, request models.CreateRemediationRequest) (models.RemediationAction, error) {
	now := time.Now().UTC()
	item := models.RemediationAction{
		ID:        nextRemediationID(),
		TenantID:  strings.TrimSpace(organizationID),
		FindingID: strings.TrimSpace(request.FindingID),
		Title:     strings.TrimSpace(request.Title),
		Status:    strings.TrimSpace(request.Status),
		Owner:     strings.TrimSpace(request.Owner),
		DueAt:     request.DueAt,
		Notes:     strings.TrimSpace(request.Notes),
		CreatedAt: now,
		UpdatedAt: now,
	}

	item.Status = normalizeRemediationStatus(item.Status)
	if item.Status == "" {
		item.Status = "open"
	}

	if item.Owner == "" || item.DueAt == nil {
		finding, err := s.loadFindingForTenant(ctx, item.TenantID, item.FindingID)
		if err != nil && !errors.Is(err, ErrTaskNotFound) {
			return models.RemediationAction{}, err
		}
		if err == nil {
			if item.Owner == "" && strings.TrimSpace(finding.Asset.OwnerTeam) != "" {
				item.Owner = strings.TrimSpace(finding.Asset.OwnerTeam)
			}
			if item.DueAt == nil && finding.Risk.SLADueAt != nil {
				dueAt := finding.Risk.SLADueAt.UTC()
				item.DueAt = &dueAt
			}
		}
	}
	if item.Owner == "" {
		item.Owner = "unassigned"
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationAction{}, fmt.Errorf("begin tenant remediation tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO remediation_actions (
			id, tenant_id, finding_id, title, status, owner, due_at, notes, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $9
		)
	`, item.ID, item.TenantID, item.FindingID, item.Title, item.Status, item.Owner, item.DueAt, item.Notes, now)
	if err != nil {
		return models.RemediationAction{}, fmt.Errorf("insert tenant remediation: %w", err)
	}

	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      item.TenantID,
		RemediationID: item.ID,
		EventType:     "created",
		Actor:         item.Owner,
		Comment:       item.Notes,
		Metadata: map[string]any{
			"status":     item.Status,
			"finding_id": item.FindingID,
		},
		CreatedAt: now,
	}); err != nil {
		return models.RemediationAction{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationAction{}, fmt.Errorf("commit tenant remediation tx: %w", err)
	}

	return item, nil
}

func (s *Store) TransitionRemediationForTenant(ctx context.Context, organizationID string, remediationID string, request models.TransitionRemediationRequest) (models.RemediationAction, bool, error) {
	now := time.Now().UTC()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationAction{}, false, fmt.Errorf("begin remediation transition tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var item models.RemediationAction
	err = tx.QueryRow(ctx, `
		SELECT tenant_id, id, finding_id, title, status, owner, due_at, notes, created_at, updated_at
		FROM remediation_actions
		WHERE tenant_id = $1
		  AND id = $2
		FOR UPDATE
	`, strings.TrimSpace(organizationID), strings.TrimSpace(remediationID)).Scan(
		&item.TenantID,
		&item.ID,
		&item.FindingID,
		&item.Title,
		&item.Status,
		&item.Owner,
		&item.DueAt,
		&item.Notes,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.RemediationAction{}, false, nil
		}
		return models.RemediationAction{}, false, fmt.Errorf("load remediation for transition: %w", err)
	}

	nextStatus := normalizeRemediationStatus(request.Status)
	if !isValidRemediationTransition(item.Status, nextStatus) {
		return models.RemediationAction{}, false, ErrInvalidRemediationTransition
	}
	previousStatus := item.Status

	if strings.TrimSpace(request.Owner) != "" {
		item.Owner = strings.TrimSpace(request.Owner)
	}
	if request.DueAt != nil {
		item.DueAt = request.DueAt
	}
	if strings.TrimSpace(request.Notes) != "" {
		if strings.TrimSpace(item.Notes) == "" {
			item.Notes = strings.TrimSpace(request.Notes)
		} else {
			item.Notes = item.Notes + "\n" + strings.TrimSpace(request.Notes)
		}
	}
	item.Status = nextStatus
	item.UpdatedAt = now

	_, err = tx.Exec(ctx, `
		UPDATE remediation_actions
		SET status = $2,
		    owner = $3,
		    due_at = $4,
		    notes = $5,
		    updated_at = $6
		WHERE id = $1
	`, item.ID, item.Status, item.Owner, item.DueAt, item.Notes, item.UpdatedAt)
	if err != nil {
		return models.RemediationAction{}, false, fmt.Errorf("update remediation transition: %w", err)
	}

	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      item.TenantID,
		RemediationID: item.ID,
		EventType:     "status_transition",
		Actor:         item.Owner,
		Comment:       strings.TrimSpace(request.Notes),
		Metadata: map[string]any{
			"from": previousStatus,
			"to":   item.Status,
		},
		CreatedAt: now,
	}); err != nil {
		return models.RemediationAction{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationAction{}, false, fmt.Errorf("commit remediation transition tx: %w", err)
	}

	return item, true, nil
}

func (s *Store) deriveRemediationDueAt(ctx context.Context, organizationID string, findingID string) (*time.Time, error) {
	var payload []byte
	err := s.pool.QueryRow(ctx, `
		SELECT finding_json
		FROM normalized_findings
		WHERE tenant_id = $1
		  AND finding_id = $2
	`, strings.TrimSpace(organizationID), strings.TrimSpace(findingID)).Scan(&payload)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("load finding for remediation due date: %w", err)
	}

	var finding models.CanonicalFinding
	if err := json.Unmarshal(payload, &finding); err != nil {
		return nil, fmt.Errorf("decode finding for remediation due date: %w", err)
	}
	if finding.Risk.SLADueAt == nil {
		return nil, nil
	}

	dueAt := finding.Risk.SLADueAt.UTC()
	return &dueAt, nil
}

func normalizeRemediationStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return ""
	case "open":
		return "open"
	case "assigned":
		return "assigned"
	case "in_progress", "in-progress":
		return "in_progress"
	case "blocked":
		return "blocked"
	case "ready_for_verify", "ready-for-verify":
		return "ready_for_verify"
	case "verified":
		return "verified"
	case "accepted_risk", "accepted-risk":
		return "accepted_risk"
	case "closed":
		return "closed"
	default:
		return ""
	}
}

func isValidRemediationTransition(current string, next string) bool {
	current = normalizeRemediationStatus(current)
	next = normalizeRemediationStatus(next)
	if next == "" {
		return false
	}
	if current == next {
		return true
	}

	allowed := map[string]map[string]struct{}{
		"open": {
			"assigned":      {},
			"in_progress":   {},
			"blocked":       {},
			"accepted_risk": {},
			"closed":        {},
		},
		"assigned": {
			"in_progress":      {},
			"blocked":          {},
			"ready_for_verify": {},
			"accepted_risk":    {},
		},
		"in_progress": {
			"blocked":          {},
			"ready_for_verify": {},
			"accepted_risk":    {},
		},
		"blocked": {
			"assigned":      {},
			"in_progress":   {},
			"accepted_risk": {},
		},
		"ready_for_verify": {
			"verified":    {},
			"in_progress": {},
			"blocked":     {},
		},
		"verified": {
			"closed": {},
		},
		"accepted_risk": {
			"closed": {},
		},
	}

	nextSet, ok := allowed[current]
	if !ok {
		return false
	}
	_, ok = nextSet[next]
	return ok
}
