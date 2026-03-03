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

func (s *Store) GetPolicyForTenant(ctx context.Context, organizationID string, policyID string) (models.Policy, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, id, version_number, name, scope, mode, enabled, rules_json, updated_by, created_at, updated_at
		FROM policies
		WHERE id = $1
		  AND (tenant_id = $2 OR tenant_id = '')
	`, strings.TrimSpace(policyID), strings.TrimSpace(organizationID))

	policy, err := scanPolicy(row)
	if err != nil {
		if isNoRows(err) {
			return models.Policy{}, false, nil
		}
		return models.Policy{}, false, err
	}

	return policy, true, nil
}

func (s *Store) UpdatePolicyForTenant(ctx context.Context, organizationID string, policyID string, request models.UpdatePolicyRequest) (models.Policy, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.Policy{}, false, fmt.Errorf("begin update policy tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		SELECT tenant_id, id, version_number, name, scope, mode, enabled, rules_json, updated_by, created_at, updated_at
		FROM policies
		WHERE id = $1
		  AND tenant_id = $2
		FOR UPDATE
	`, strings.TrimSpace(policyID), strings.TrimSpace(organizationID))

	current, err := scanPolicy(row)
	if err != nil {
		if isNoRows(err) {
			return models.Policy{}, false, nil
		}
		return models.Policy{}, false, err
	}

	current.VersionNumber++
	current.Name = strings.TrimSpace(request.Name)
	current.Scope = strings.TrimSpace(request.Scope)
	current.Mode = strings.TrimSpace(request.Mode)
	current.Enabled = request.Enabled
	current.Rules = sanitizeRuleList(request.Rules)
	current.UpdatedBy = strings.TrimSpace(request.UpdatedBy)
	current.UpdatedAt = time.Now().UTC()

	if current.Scope == "" {
		current.Scope = "tenant"
	}
	if current.Mode == "" {
		current.Mode = "monitor"
	}

	rulesJSON, err := json.Marshal(current.Rules)
	if err != nil {
		return models.Policy{}, false, fmt.Errorf("marshal updated policy rules: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE policies
		SET version_number = $2,
		    name = $3,
		    scope = $4,
		    mode = $5,
		    enabled = $6,
		    rules_json = $7,
		    updated_by = $8,
		    updated_at = $9
		WHERE id = $1
		  AND tenant_id = $10
	`, current.ID, current.VersionNumber, current.Name, current.Scope, current.Mode, current.Enabled, rulesJSON, current.UpdatedBy, current.UpdatedAt, current.TenantID)
	if err != nil {
		return models.Policy{}, false, fmt.Errorf("update policy: %w", err)
	}

	if err := recordPolicyVersionTx(ctx, tx, current, "updated", current.UpdatedBy); err != nil {
		return models.Policy{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.Policy{}, false, fmt.Errorf("commit update policy tx: %w", err)
	}

	return current, true, nil
}

func (s *Store) ListPolicyVersionsForTenant(ctx context.Context, organizationID string, policyID string, limit int) ([]models.PolicyVersion, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT v.id, v.policy_id, v.version_number, v.change_type, v.snapshot_json, v.created_by, v.created_at
		FROM policy_versions v
		INNER JOIN policies p ON p.id = v.policy_id
		WHERE v.policy_id = $1
		  AND (p.tenant_id = $2 OR p.tenant_id = '')
		ORDER BY v.version_number DESC
		LIMIT $3
	`, strings.TrimSpace(policyID), strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list policy versions: %w", err)
	}
	defer rows.Close()

	out := make([]models.PolicyVersion, 0, limit)
	for rows.Next() {
		version, err := scanPolicyVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, version)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy versions: %w", err)
	}

	return out, nil
}

func (s *Store) RollbackPolicyForTenant(ctx context.Context, organizationID string, policyID string, versionNumber int64, updatedBy string) (models.Policy, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.Policy{}, false, fmt.Errorf("begin rollback policy tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		SELECT tenant_id, id, version_number, name, scope, mode, enabled, rules_json, updated_by, created_at, updated_at
		FROM policies
		WHERE id = $1
		  AND tenant_id = $2
		FOR UPDATE
	`, strings.TrimSpace(policyID), strings.TrimSpace(organizationID))

	current, err := scanPolicy(row)
	if err != nil {
		if isNoRows(err) {
			return models.Policy{}, false, nil
		}
		return models.Policy{}, false, err
	}

	versionRow := tx.QueryRow(ctx, `
		SELECT id, policy_id, version_number, change_type, snapshot_json, created_by, created_at
		FROM policy_versions
		WHERE policy_id = $1
		  AND version_number = $2
	`, current.ID, versionNumber)

	version, err := scanPolicyVersion(versionRow)
	if err != nil {
		if isNoRows(err) {
			return models.Policy{}, false, nil
		}
		return models.Policy{}, false, err
	}

	current.VersionNumber++
	current.Name = version.Snapshot.Name
	current.Scope = version.Snapshot.Scope
	current.Mode = version.Snapshot.Mode
	current.Enabled = version.Snapshot.Enabled
	current.Rules = sanitizeRuleList(version.Snapshot.Rules)
	current.UpdatedBy = strings.TrimSpace(updatedBy)
	current.UpdatedAt = time.Now().UTC()

	rulesJSON, err := json.Marshal(current.Rules)
	if err != nil {
		return models.Policy{}, false, fmt.Errorf("marshal rollback policy rules: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE policies
		SET version_number = $2,
		    name = $3,
		    scope = $4,
		    mode = $5,
		    enabled = $6,
		    rules_json = $7,
		    updated_by = $8,
		    updated_at = $9
		WHERE id = $1
		  AND tenant_id = $10
	`, current.ID, current.VersionNumber, current.Name, current.Scope, current.Mode, current.Enabled, rulesJSON, current.UpdatedBy, current.UpdatedAt, current.TenantID)
	if err != nil {
		return models.Policy{}, false, fmt.Errorf("rollback policy: %w", err)
	}

	if err := recordPolicyVersionTx(ctx, tx, current, "rolled_back", current.UpdatedBy); err != nil {
		return models.Policy{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.Policy{}, false, fmt.Errorf("commit rollback policy tx: %w", err)
	}

	return current, true, nil
}

func (s *Store) ListPolicyApprovalsForTenant(ctx context.Context, organizationID string, limit int) ([]models.PolicyApproval, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, scan_job_id, task_id, policy_id, action, status, requested_by,
		       decided_by, reason, created_at, decided_at
		FROM policy_approvals
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list policy approvals: %w", err)
	}
	defer rows.Close()

	out := make([]models.PolicyApproval, 0, limit)
	for rows.Next() {
		approval, err := scanPolicyApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, approval)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy approvals: %w", err)
	}

	return out, nil
}

func (s *Store) DecidePolicyApproval(ctx context.Context, organizationID string, approvalID string, approved bool, decidedBy string, reason string) (models.PolicyApproval, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.PolicyApproval{}, false, fmt.Errorf("begin policy approval tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		SELECT id, tenant_id, scan_job_id, task_id, policy_id, action, status, requested_by,
		       decided_by, reason, created_at, decided_at
		FROM policy_approvals
		WHERE id = $1
		  AND tenant_id = $2
		FOR UPDATE
	`, strings.TrimSpace(approvalID), strings.TrimSpace(organizationID))

	item, err := scanPolicyApproval(row)
	if err != nil {
		if isNoRows(err) {
			return models.PolicyApproval{}, false, nil
		}
		return models.PolicyApproval{}, false, err
	}

	if item.Status != "pending" {
		if err := tx.Commit(ctx); err != nil {
			return models.PolicyApproval{}, false, fmt.Errorf("commit unchanged policy approval tx: %w", err)
		}
		return item, true, nil
	}

	now := time.Now().UTC()
	item.Status = "denied"
	if approved {
		item.Status = "approved"
	}
	item.DecidedBy = strings.TrimSpace(decidedBy)
	item.Reason = strings.TrimSpace(reason)
	item.DecidedAt = &now

	_, err = tx.Exec(ctx, `
		UPDATE policy_approvals
		SET status = $2,
		    decided_by = $3,
		    reason = $4,
		    decided_at = $5
		WHERE id = $1
	`, item.ID, item.Status, item.DecidedBy, item.Reason, now)
	if err != nil {
		return models.PolicyApproval{}, false, fmt.Errorf("update policy approval: %w", err)
	}

	if approved {
		_, err = tx.Exec(ctx, `
			UPDATE scan_job_tasks
			SET policy_status = 'approved',
			    policy_reason = $2,
			    updated_at = $3
			WHERE id = $1
		`, item.TaskID, item.Reason, now)
		if err != nil {
			return models.PolicyApproval{}, false, fmt.Errorf("approve task for policy approval: %w", err)
		}
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE scan_job_tasks
			SET policy_status = 'denied',
			    policy_reason = $2,
			    status = 'canceled',
			    updated_at = $3
			WHERE id = $1
		`, item.TaskID, item.Reason, now)
		if err != nil {
			return models.PolicyApproval{}, false, fmt.Errorf("deny task for policy approval: %w", err)
		}

		if err := recomputeScanJobStatusTx(ctx, tx, item.ScanJobID, now); err != nil {
			return models.PolicyApproval{}, false, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return models.PolicyApproval{}, false, fmt.Errorf("commit policy approval tx: %w", err)
	}

	return item, true, nil
}

func recordPolicyVersionTx(ctx context.Context, tx pgx.Tx, policy models.Policy, changeType string, createdBy string) error {
	if strings.TrimSpace(createdBy) == "" {
		createdBy = "system"
	}

	snapshotJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshal policy version snapshot: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO policy_versions (
			id, policy_id, version_number, change_type, snapshot_json, created_by, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
	`, nextPolicyVersionID(), policy.ID, policy.VersionNumber, strings.TrimSpace(changeType), snapshotJSON, strings.TrimSpace(createdBy), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("insert policy version: %w", err)
	}

	return nil
}

type policyScanner interface {
	Scan(dest ...any) error
}

func scanPolicy(scanner policyScanner) (models.Policy, error) {
	var policy models.Policy
	var rulesJSON []byte

	err := scanner.Scan(
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
	)
	if err != nil {
		if isNoRows(err) {
			return models.Policy{}, err
		}
		return models.Policy{}, fmt.Errorf("scan policy: %w", err)
	}

	if len(rulesJSON) > 0 {
		if err := json.Unmarshal(rulesJSON, &policy.Rules); err != nil {
			return models.Policy{}, fmt.Errorf("unmarshal policy rules: %w", err)
		}
	}

	return policy, nil
}

func scanPolicyVersion(scanner policyScanner) (models.PolicyVersion, error) {
	var version models.PolicyVersion
	var snapshotJSON []byte

	err := scanner.Scan(
		&version.ID,
		&version.PolicyID,
		&version.VersionNumber,
		&version.ChangeType,
		&snapshotJSON,
		&version.CreatedBy,
		&version.CreatedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.PolicyVersion{}, err
		}
		return models.PolicyVersion{}, fmt.Errorf("scan policy version: %w", err)
	}

	if len(snapshotJSON) > 0 {
		if err := json.Unmarshal(snapshotJSON, &version.Snapshot); err != nil {
			return models.PolicyVersion{}, fmt.Errorf("unmarshal policy version snapshot: %w", err)
		}
	}

	return version, nil
}

func scanPolicyApproval(scanner policyScanner) (models.PolicyApproval, error) {
	var item models.PolicyApproval
	err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.ScanJobID,
		&item.TaskID,
		&item.PolicyID,
		&item.Action,
		&item.Status,
		&item.RequestedBy,
		&item.DecidedBy,
		&item.Reason,
		&item.CreatedAt,
		&item.DecidedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.PolicyApproval{}, err
		}
		return models.PolicyApproval{}, fmt.Errorf("scan policy approval: %w", err)
	}

	return item, nil
}
