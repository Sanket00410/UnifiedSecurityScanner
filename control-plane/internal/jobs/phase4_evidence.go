package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListRemediationEvidenceForTenant(ctx context.Context, organizationID string, remediationID string, limit int) ([]models.RemediationEvidence, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, remediation_id, kind, name, ref, summary, created_by, created_at, updated_at
		FROM remediation_evidence
		WHERE tenant_id = $1
		  AND remediation_id = $2
		ORDER BY updated_at DESC
		LIMIT $3
	`, strings.TrimSpace(organizationID), strings.TrimSpace(remediationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list remediation evidence: %w", err)
	}
	defer rows.Close()

	out := make([]models.RemediationEvidence, 0, limit)
	for rows.Next() {
		item, err := scanRemediationEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate remediation evidence: %w", err)
	}

	return out, nil
}

func (s *Store) CreateRemediationEvidenceForTenant(ctx context.Context, organizationID string, remediationID string, actor string, request models.CreateRemediationEvidenceRequest) (models.RemediationEvidence, error) {
	if strings.TrimSpace(request.Kind) == "" || strings.TrimSpace(request.Ref) == "" {
		return models.RemediationEvidence{}, ErrInvalidRemediationTransition
	}

	if _, found, err := s.GetRemediationForTenant(ctx, organizationID, remediationID); err != nil {
		return models.RemediationEvidence{}, err
	} else if !found {
		return models.RemediationEvidence{}, ErrTaskNotFound
	}

	now := time.Now().UTC()
	item := models.RemediationEvidence{
		ID:            nextRemediationEvidenceID(),
		TenantID:      strings.TrimSpace(organizationID),
		RemediationID: strings.TrimSpace(remediationID),
		Kind:          strings.ToLower(strings.TrimSpace(request.Kind)),
		Name:          strings.TrimSpace(request.Name),
		Ref:           strings.TrimSpace(request.Ref),
		Summary:       strings.TrimSpace(request.Summary),
		CreatedBy:     strings.TrimSpace(actor),
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationEvidence{}, fmt.Errorf("begin remediation evidence tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO remediation_evidence (
			id, tenant_id, remediation_id, kind, name, ref, summary, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $9
		)
	`, item.ID, item.TenantID, item.RemediationID, item.Kind, item.Name, item.Ref, item.Summary, item.CreatedBy, now)
	if err != nil {
		return models.RemediationEvidence{}, fmt.Errorf("insert remediation evidence: %w", err)
	}

	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      item.TenantID,
		RemediationID: item.RemediationID,
		EventType:     "evidence_added",
		Actor:         item.CreatedBy,
		Comment:       item.Summary,
		Metadata: map[string]any{
			"evidence_id":   item.ID,
			"evidence_kind": item.Kind,
			"evidence_ref":  item.Ref,
		},
		CreatedAt: now,
	}); err != nil {
		return models.RemediationEvidence{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationEvidence{}, fmt.Errorf("commit remediation evidence tx: %w", err)
	}

	return item, nil
}

func scanRemediationEvidence(scanner interface{ Scan(dest ...any) error }) (models.RemediationEvidence, error) {
	var item models.RemediationEvidence
	err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.RemediationID,
		&item.Kind,
		&item.Name,
		&item.Ref,
		&item.Summary,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.RemediationEvidence{}, fmt.Errorf("scan remediation evidence: %w", err)
	}
	return item, nil
}
