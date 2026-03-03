package jobs

import (
	"context"
	"encoding/json"
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
		ORDER BY updated_at DESC
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

	return out, nil
}

func (s *Store) ListAssetsForTenant(ctx context.Context, organizationID string, limit int) ([]models.AssetSummary, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			sj.target,
			sj.target_kind,
			MAX(sj.updated_at) AS last_scanned_at,
			COUNT(DISTINCT sj.id) AS scan_count,
			COUNT(nf.finding_id) AS finding_count
		FROM scan_jobs sj
		LEFT JOIN normalized_findings nf ON nf.scan_job_id = sj.id
		WHERE sj.tenant_id = $1
		GROUP BY sj.target, sj.target_kind
		ORDER BY MAX(sj.updated_at) DESC
		LIMIT $2
	`, strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list tenant assets: %w", err)
	}
	defer rows.Close()

	out := make([]models.AssetSummary, 0, limit)
	for rows.Next() {
		var asset models.AssetSummary
		if err := rows.Scan(
			&asset.AssetID,
			&asset.AssetType,
			&asset.LastScannedAt,
			&asset.ScanCount,
			&asset.FindingCount,
		); err != nil {
			return nil, fmt.Errorf("scan tenant asset: %w", err)
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

	if item.Status == "" {
		item.Status = "open"
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO remediation_actions (
			id, tenant_id, finding_id, title, status, owner, due_at, notes, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $9
		)
	`, item.ID, item.TenantID, item.FindingID, item.Title, item.Status, item.Owner, item.DueAt, item.Notes, now)
	if err != nil {
		return models.RemediationAction{}, fmt.Errorf("insert tenant remediation: %w", err)
	}

	return item, nil
}
