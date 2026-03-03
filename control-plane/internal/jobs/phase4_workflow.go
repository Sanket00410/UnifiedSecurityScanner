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

func (s *Store) ListRemediationActivityForTenant(ctx context.Context, organizationID string, remediationID string, limit int) ([]models.RemediationActivity, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, remediation_id, event_type, actor, comment, metadata_json, created_at
		FROM remediation_activities
		WHERE tenant_id = $1
		  AND remediation_id = $2
		ORDER BY created_at DESC
		LIMIT $3
	`, strings.TrimSpace(organizationID), strings.TrimSpace(remediationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list remediation activity: %w", err)
	}
	defer rows.Close()

	out := make([]models.RemediationActivity, 0, limit)
	for rows.Next() {
		item, err := scanRemediationActivity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate remediation activity: %w", err)
	}

	return out, nil
}

func (s *Store) CreateRemediationCommentForTenant(ctx context.Context, organizationID string, remediationID string, actor string, request models.CreateRemediationCommentRequest) (models.RemediationActivity, error) {
	if strings.TrimSpace(request.Comment) == "" {
		return models.RemediationActivity{}, ErrInvalidRemediationTransition
	}

	if _, found, err := s.GetRemediationForTenant(ctx, organizationID, remediationID); err != nil {
		return models.RemediationActivity{}, err
	} else if !found {
		return models.RemediationActivity{}, ErrTaskNotFound
	}

	now := time.Now().UTC()
	activity := models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      strings.TrimSpace(organizationID),
		RemediationID: strings.TrimSpace(remediationID),
		EventType:     "comment",
		Actor:         strings.TrimSpace(actor),
		Comment:       strings.TrimSpace(request.Comment),
		Metadata:      map[string]any{"kind": "comment"},
		CreatedAt:     now,
	}

	if err := s.insertRemediationActivity(ctx, activity); err != nil {
		return models.RemediationActivity{}, err
	}

	return activity, nil
}

func (s *Store) ListRemediationVerificationsForTenant(ctx context.Context, organizationID string, remediationID string, limit int) ([]models.RemediationVerification, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, remediation_id, finding_id, scan_job_id, status, outcome, requested_by, verified_by, notes,
		       requested_at, verified_at, created_at, updated_at
		FROM remediation_verifications
		WHERE tenant_id = $1
		  AND remediation_id = $2
		ORDER BY updated_at DESC
		LIMIT $3
	`, strings.TrimSpace(organizationID), strings.TrimSpace(remediationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list remediation verifications: %w", err)
	}
	defer rows.Close()

	out := make([]models.RemediationVerification, 0, limit)
	for rows.Next() {
		item, err := scanRemediationVerification(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate remediation verifications: %w", err)
	}

	return out, nil
}

func (s *Store) RequestRemediationRetestForTenant(ctx context.Context, organizationID string, remediationID string, actor string, request models.CreateRetestRequest) (models.RemediationVerification, models.ScanJob, error) {
	remediation, found, err := s.GetRemediationForTenant(ctx, organizationID, remediationID)
	if err != nil {
		return models.RemediationVerification{}, models.ScanJob{}, err
	}
	if !found {
		return models.RemediationVerification{}, models.ScanJob{}, ErrTaskNotFound
	}

	currentStatus := normalizeRemediationStatus(remediation.Status)
	if currentStatus != "ready_for_verify" && currentStatus != "in_progress" && currentStatus != "assigned" {
		return models.RemediationVerification{}, models.ScanJob{}, ErrInvalidVerification
	}

	finding, err := s.loadFindingForTenant(ctx, organizationID, remediation.FindingID)
	if err != nil {
		return models.RemediationVerification{}, models.ScanJob{}, err
	}

	tool := strings.ToLower(strings.TrimSpace(firstNonEmptyFindingTool(finding)))
	if tool == "" {
		tool = "zap"
	}

	job, err := s.CreateForTenant(ctx, organizationID, models.CreateScanJobRequest{
		TargetKind:  finding.Asset.AssetType,
		Target:      finding.Asset.AssetID,
		Profile:     "retest",
		RequestedBy: strings.TrimSpace(actor),
		Tools:       []string{tool},
	})
	if err != nil {
		return models.RemediationVerification{}, models.ScanJob{}, err
	}

	now := time.Now().UTC()
	verification := models.RemediationVerification{
		ID:            nextVerificationID(),
		TenantID:      strings.TrimSpace(organizationID),
		RemediationID: remediation.ID,
		FindingID:     remediation.FindingID,
		ScanJobID:     job.ID,
		Status:        "requested",
		RequestedBy:   strings.TrimSpace(actor),
		Notes:         strings.TrimSpace(request.Notes),
		RequestedAt:   now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationVerification{}, models.ScanJob{}, fmt.Errorf("begin remediation retest tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO remediation_verifications (
			id, tenant_id, remediation_id, finding_id, scan_job_id, status, outcome, requested_by, verified_by, notes,
			requested_at, verified_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, '', $7, '', $8,
			$9, NULL, $9, $9
		)
	`, verification.ID, verification.TenantID, verification.RemediationID, verification.FindingID, verification.ScanJobID, verification.Status, verification.RequestedBy, verification.Notes, verification.RequestedAt)
	if err != nil {
		return models.RemediationVerification{}, models.ScanJob{}, fmt.Errorf("insert remediation verification: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE remediation_actions
		SET status = 'ready_for_verify',
		    updated_at = $2
		WHERE tenant_id = $1
		  AND id = $3
	`, verification.TenantID, now, remediation.ID); err != nil {
		return models.RemediationVerification{}, models.ScanJob{}, fmt.Errorf("mark remediation ready_for_verify: %w", err)
	}

	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      verification.TenantID,
		RemediationID: remediation.ID,
		EventType:     "retest_requested",
		Actor:         verification.RequestedBy,
		Comment:       verification.Notes,
		Metadata: map[string]any{
			"verification_id": verification.ID,
			"scan_job_id":     verification.ScanJobID,
		},
		CreatedAt: now,
	}); err != nil {
		return models.RemediationVerification{}, models.ScanJob{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationVerification{}, models.ScanJob{}, fmt.Errorf("commit remediation retest tx: %w", err)
	}

	return verification, job, nil
}

func (s *Store) RecordRemediationVerificationForTenant(ctx context.Context, organizationID string, remediationID string, actor string, request models.RecordRemediationVerificationRequest) (models.RemediationVerification, bool, error) {
	if strings.TrimSpace(request.VerificationID) == "" {
		return models.RemediationVerification{}, false, ErrInvalidVerification
	}
	outcome := normalizeVerificationOutcome(request.Outcome)
	if outcome == "" {
		return models.RemediationVerification{}, false, ErrInvalidVerification
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationVerification{}, false, fmt.Errorf("begin remediation verification tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var verification models.RemediationVerification
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, remediation_id, finding_id, scan_job_id, status, outcome, requested_by, verified_by, notes,
		       requested_at, verified_at, created_at, updated_at
		FROM remediation_verifications
		WHERE tenant_id = $1
		  AND remediation_id = $2
		  AND id = $3
		FOR UPDATE
	`, strings.TrimSpace(organizationID), strings.TrimSpace(remediationID), strings.TrimSpace(request.VerificationID)).Scan(
		&verification.ID,
		&verification.TenantID,
		&verification.RemediationID,
		&verification.FindingID,
		&verification.ScanJobID,
		&verification.Status,
		&verification.Outcome,
		&verification.RequestedBy,
		&verification.VerifiedBy,
		&verification.Notes,
		&verification.RequestedAt,
		&verification.VerifiedAt,
		&verification.CreatedAt,
		&verification.UpdatedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.RemediationVerification{}, false, nil
		}
		return models.RemediationVerification{}, false, fmt.Errorf("load remediation verification: %w", err)
	}

	if strings.ToLower(strings.TrimSpace(verification.Status)) != "requested" {
		return models.RemediationVerification{}, false, ErrInvalidVerification
	}

	now := time.Now().UTC()
	verification.Status = "completed"
	verification.Outcome = outcome
	verification.VerifiedBy = strings.TrimSpace(actor)
	if strings.TrimSpace(request.Notes) != "" {
		if strings.TrimSpace(verification.Notes) == "" {
			verification.Notes = strings.TrimSpace(request.Notes)
		} else {
			verification.Notes = verification.Notes + "\n" + strings.TrimSpace(request.Notes)
		}
	}
	verification.UpdatedAt = now
	verification.VerifiedAt = &now

	_, err = tx.Exec(ctx, `
		UPDATE remediation_verifications
		SET status = $2,
		    outcome = $3,
		    verified_by = $4,
		    notes = $5,
		    verified_at = $6,
		    updated_at = $6
		WHERE id = $1
	`, verification.ID, verification.Status, verification.Outcome, verification.VerifiedBy, verification.Notes, now)
	if err != nil {
		return models.RemediationVerification{}, false, fmt.Errorf("update remediation verification: %w", err)
	}

	nextRemediationStatus := "verified"
	eventType := "verification_passed"
	comment := "verification passed"
	if outcome == "failed" {
		nextRemediationStatus = "in_progress"
		eventType = "verification_failed"
		comment = "verification failed"
	}

	_, err = tx.Exec(ctx, `
		UPDATE remediation_actions
		SET status = $2,
		    updated_at = $3
		WHERE tenant_id = $1
		  AND id = $4
	`, verification.TenantID, nextRemediationStatus, now, verification.RemediationID)
	if err != nil {
		return models.RemediationVerification{}, false, fmt.Errorf("update remediation status from verification: %w", err)
	}

	if outcome == "passed" {
		if _, err := setStoredFindingStatusTx(ctx, tx, verification.TenantID, verification.FindingID, "resolved", now); err != nil {
			return models.RemediationVerification{}, false, err
		}
	} else {
		if _, err := setStoredFindingStatusTx(ctx, tx, verification.TenantID, verification.FindingID, "open", now); err != nil {
			return models.RemediationVerification{}, false, err
		}
	}

	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      verification.TenantID,
		RemediationID: verification.RemediationID,
		EventType:     eventType,
		Actor:         verification.VerifiedBy,
		Comment:       firstNonEmptyString(strings.TrimSpace(request.Notes), comment),
		Metadata: map[string]any{
			"verification_id": verification.ID,
			"outcome":         verification.Outcome,
			"scan_job_id":     verification.ScanJobID,
		},
		CreatedAt: now,
	}); err != nil {
		return models.RemediationVerification{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationVerification{}, false, fmt.Errorf("commit remediation verification tx: %w", err)
	}

	return verification, true, nil
}

func (s *Store) ListRemediationExceptionsForTenant(ctx context.Context, organizationID string, remediationID string, limit int) ([]models.RemediationException, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, remediation_id, finding_id, reason, reduction, notes, status, requested_by, decided_by, expires_at, created_at, updated_at, decided_at
		FROM remediation_exceptions
		WHERE tenant_id = $1
		  AND remediation_id = $2
		ORDER BY updated_at DESC
		LIMIT $3
	`, strings.TrimSpace(organizationID), strings.TrimSpace(remediationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list remediation exceptions: %w", err)
	}
	defer rows.Close()

	out := make([]models.RemediationException, 0, limit)
	for rows.Next() {
		item, err := scanRemediationException(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate remediation exceptions: %w", err)
	}

	return out, nil
}

func (s *Store) CreateRemediationExceptionForTenant(ctx context.Context, organizationID string, remediationID string, actor string, request models.CreateRemediationExceptionRequest) (models.RemediationException, error) {
	if strings.TrimSpace(request.Reason) == "" || request.Reduction <= 0 {
		return models.RemediationException{}, ErrInvalidExceptionDecision
	}

	remediation, found, err := s.GetRemediationForTenant(ctx, organizationID, remediationID)
	if err != nil {
		return models.RemediationException{}, err
	}
	if !found {
		return models.RemediationException{}, ErrTaskNotFound
	}

	now := time.Now().UTC()
	item := models.RemediationException{
		ID:            nextExceptionID(),
		TenantID:      strings.TrimSpace(organizationID),
		RemediationID: remediation.ID,
		FindingID:     remediation.FindingID,
		Reason:        strings.TrimSpace(request.Reason),
		Reduction:     clampWaiverReduction(request.Reduction),
		Notes:         strings.TrimSpace(request.Notes),
		Status:        "pending",
		RequestedBy:   strings.TrimSpace(actor),
		ExpiresAt:     request.ExpiresAt,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationException{}, fmt.Errorf("begin remediation exception tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO remediation_exceptions (
			id, tenant_id, remediation_id, finding_id, reason, reduction, notes, status, requested_by, decided_by, expires_at, created_at, updated_at, decided_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, '', $10, $11, $11, NULL
		)
	`, item.ID, item.TenantID, item.RemediationID, item.FindingID, item.Reason, item.Reduction, item.Notes, item.Status, item.RequestedBy, item.ExpiresAt, now)
	if err != nil {
		return models.RemediationException{}, fmt.Errorf("insert remediation exception: %w", err)
	}

	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      item.TenantID,
		RemediationID: item.RemediationID,
		EventType:     "exception_requested",
		Actor:         item.RequestedBy,
		Comment:       item.Notes,
		Metadata: map[string]any{
			"exception_id": item.ID,
			"reduction":    item.Reduction,
		},
		CreatedAt: now,
	}); err != nil {
		return models.RemediationException{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationException{}, fmt.Errorf("commit remediation exception tx: %w", err)
	}

	return item, nil
}

func (s *Store) DecideRemediationExceptionForTenant(ctx context.Context, organizationID string, exceptionID string, approved bool, actor string, reason string) (models.RemediationException, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationException{}, false, fmt.Errorf("begin remediation exception decision tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var item models.RemediationException
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, remediation_id, finding_id, reason, reduction, notes, status, requested_by, decided_by, expires_at, created_at, updated_at, decided_at
		FROM remediation_exceptions
		WHERE tenant_id = $1
		  AND id = $2
		FOR UPDATE
	`, strings.TrimSpace(organizationID), strings.TrimSpace(exceptionID)).Scan(
		&item.ID,
		&item.TenantID,
		&item.RemediationID,
		&item.FindingID,
		&item.Reason,
		&item.Reduction,
		&item.Notes,
		&item.Status,
		&item.RequestedBy,
		&item.DecidedBy,
		&item.ExpiresAt,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.DecidedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.RemediationException{}, false, nil
		}
		return models.RemediationException{}, false, fmt.Errorf("load remediation exception: %w", err)
	}

	if strings.ToLower(strings.TrimSpace(item.Status)) != "pending" {
		return models.RemediationException{}, false, ErrInvalidExceptionDecision
	}

	now := time.Now().UTC()
	item.DecidedBy = strings.TrimSpace(actor)
	item.DecidedAt = &now
	item.UpdatedAt = now
	if approved {
		item.Status = "approved"
	} else {
		item.Status = "denied"
	}
	if strings.TrimSpace(reason) != "" {
		if strings.TrimSpace(item.Notes) == "" {
			item.Notes = strings.TrimSpace(reason)
		} else {
			item.Notes = item.Notes + "\n" + strings.TrimSpace(reason)
		}
	}

	_, err = tx.Exec(ctx, `
		UPDATE remediation_exceptions
		SET status = $2,
		    notes = $3,
		    decided_by = $4,
		    decided_at = $5,
		    updated_at = $5
		WHERE id = $1
	`, item.ID, item.Status, item.Notes, item.DecidedBy, now)
	if err != nil {
		return models.RemediationException{}, false, fmt.Errorf("update remediation exception: %w", err)
	}

	if approved {
		_, err = tx.Exec(ctx, `
			UPDATE remediation_actions
			SET status = 'accepted_risk',
			    updated_at = $2
			WHERE tenant_id = $1
			  AND id = $3
		`, item.TenantID, now, item.RemediationID)
		if err != nil {
			return models.RemediationException{}, false, fmt.Errorf("mark remediation accepted_risk: %w", err)
		}

		waiver := models.FindingWaiver{
			ID:            nextWaiverID(),
			TenantID:      item.TenantID,
			FindingID:     item.FindingID,
			RemediationID: item.RemediationID,
			Reason:        firstNonEmptyString(strings.TrimSpace(reason), item.Reason),
			Reduction:     clampWaiverReduction(item.Reduction),
			Status:        "approved",
			ExpiresAt:     item.ExpiresAt,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		waiver.Status = deriveWaiverStatus(waiver, "accepted_risk", "", now)

		_, err = tx.Exec(ctx, `
			INSERT INTO finding_waivers (
				id, tenant_id, finding_id, remediation_id, policy_approval_id, reason, reduction, status, expires_at, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, '', $5, $6, $7, $8, $9, $9
			)
		`, waiver.ID, waiver.TenantID, waiver.FindingID, waiver.RemediationID, waiver.Reason, waiver.Reduction, waiver.Status, waiver.ExpiresAt, now)
		if err != nil {
			return models.RemediationException{}, false, fmt.Errorf("insert approved exception waiver: %w", err)
		}
	}

	eventType := "exception_denied"
	if approved {
		eventType = "exception_approved"
	}
	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      item.TenantID,
		RemediationID: item.RemediationID,
		EventType:     eventType,
		Actor:         item.DecidedBy,
		Comment:       strings.TrimSpace(reason),
		Metadata: map[string]any{
			"exception_id": item.ID,
			"status":       item.Status,
		},
		CreatedAt: now,
	}); err != nil {
		return models.RemediationException{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationException{}, false, fmt.Errorf("commit remediation exception decision tx: %w", err)
	}

	return item, true, nil
}

func (s *Store) ListRemediationTicketLinksForTenant(ctx context.Context, organizationID string, remediationID string, limit int) ([]models.RemediationTicketLink, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, remediation_id, provider, external_id, title, url, status, created_at, updated_at
		FROM remediation_ticket_links
		WHERE tenant_id = $1
		  AND remediation_id = $2
		ORDER BY updated_at DESC
		LIMIT $3
	`, strings.TrimSpace(organizationID), strings.TrimSpace(remediationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list remediation ticket links: %w", err)
	}
	defer rows.Close()

	out := make([]models.RemediationTicketLink, 0, limit)
	for rows.Next() {
		item, err := scanRemediationTicketLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate remediation ticket links: %w", err)
	}

	return out, nil
}

func (s *Store) CreateRemediationTicketLinkForTenant(ctx context.Context, organizationID string, remediationID string, request models.CreateRemediationTicketLinkRequest) (models.RemediationTicketLink, error) {
	if strings.TrimSpace(request.Provider) == "" || strings.TrimSpace(request.ExternalID) == "" {
		return models.RemediationTicketLink{}, ErrInvalidExceptionDecision
	}
	if _, found, err := s.GetRemediationForTenant(ctx, organizationID, remediationID); err != nil {
		return models.RemediationTicketLink{}, err
	} else if !found {
		return models.RemediationTicketLink{}, ErrTaskNotFound
	}

	now := time.Now().UTC()
	item := models.RemediationTicketLink{
		ID:            nextTicketID(),
		TenantID:      strings.TrimSpace(organizationID),
		RemediationID: strings.TrimSpace(remediationID),
		Provider:      strings.ToLower(strings.TrimSpace(request.Provider)),
		ExternalID:    strings.TrimSpace(request.ExternalID),
		Title:         strings.TrimSpace(request.Title),
		URL:           strings.TrimSpace(request.URL),
		Status:        strings.ToLower(strings.TrimSpace(request.Status)),
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationTicketLink{}, fmt.Errorf("begin remediation ticket tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO remediation_ticket_links (
			id, tenant_id, remediation_id, provider, external_id, title, url, status, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $9
		)
	`, item.ID, item.TenantID, item.RemediationID, item.Provider, item.ExternalID, item.Title, item.URL, item.Status, now)
	if err != nil {
		return models.RemediationTicketLink{}, fmt.Errorf("insert remediation ticket link: %w", err)
	}

	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      item.TenantID,
		RemediationID: item.RemediationID,
		EventType:     "ticket_linked",
		Actor:         "",
		Comment:       item.Title,
		Metadata: map[string]any{
			"ticket_id":     item.ID,
			"provider":      item.Provider,
			"external_id":   item.ExternalID,
			"ticket_url":    item.URL,
			"ticket_status": item.Status,
		},
		CreatedAt: now,
	}); err != nil {
		return models.RemediationTicketLink{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationTicketLink{}, fmt.Errorf("commit remediation ticket tx: %w", err)
	}

	return item, nil
}

func (s *Store) insertRemediationActivity(ctx context.Context, activity models.RemediationActivity) error {
	metadataJSON, err := json.Marshal(activity.Metadata)
	if err != nil {
		return fmt.Errorf("marshal remediation activity metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO remediation_activities (
			id, tenant_id, remediation_id, event_type, actor, comment, metadata_json, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
	`, activity.ID, activity.TenantID, activity.RemediationID, activity.EventType, activity.Actor, activity.Comment, metadataJSON, activity.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert remediation activity: %w", err)
	}

	return nil
}

func insertRemediationActivityTx(ctx context.Context, tx pgx.Tx, activity models.RemediationActivity) error {
	metadataJSON, err := json.Marshal(activity.Metadata)
	if err != nil {
		return fmt.Errorf("marshal remediation activity metadata: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO remediation_activities (
			id, tenant_id, remediation_id, event_type, actor, comment, metadata_json, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
	`, activity.ID, activity.TenantID, activity.RemediationID, activity.EventType, activity.Actor, activity.Comment, metadataJSON, activity.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert remediation activity: %w", err)
	}

	return nil
}

func (s *Store) loadFindingForTenant(ctx context.Context, organizationID string, findingID string) (models.CanonicalFinding, error) {
	var payload []byte
	err := s.pool.QueryRow(ctx, `
		SELECT finding_json
		FROM normalized_findings
		WHERE tenant_id = $1
		  AND finding_id = $2
	`, strings.TrimSpace(organizationID), strings.TrimSpace(findingID)).Scan(&payload)
	if err != nil {
		if isNoRows(err) {
			return models.CanonicalFinding{}, ErrTaskNotFound
		}
		return models.CanonicalFinding{}, fmt.Errorf("load finding: %w", err)
	}

	var finding models.CanonicalFinding
	if err := json.Unmarshal(payload, &finding); err != nil {
		return models.CanonicalFinding{}, fmt.Errorf("decode finding: %w", err)
	}
	return finding, nil
}

func setStoredFindingStatusTx(ctx context.Context, tx pgx.Tx, tenantID string, findingID string, nextStatus string, now time.Time) (models.CanonicalFinding, error) {
	var payload []byte
	var reopenedCount int64
	var currentStatus string
	err := tx.QueryRow(ctx, `
		SELECT finding_json, reopened_count, current_status
		FROM normalized_findings
		WHERE tenant_id = $1
		  AND finding_id = $2
		FOR UPDATE
	`, strings.TrimSpace(tenantID), strings.TrimSpace(findingID)).Scan(&payload, &reopenedCount, &currentStatus)
	if err != nil {
		return models.CanonicalFinding{}, fmt.Errorf("load stored finding for status update: %w", err)
	}

	var finding models.CanonicalFinding
	if err := json.Unmarshal(payload, &finding); err != nil {
		return models.CanonicalFinding{}, fmt.Errorf("decode stored finding for status update: %w", err)
	}

	normalizedNext := normalizeStoredFindingStatus(nextStatus)
	if normalizedNext == "open" && shouldReopenFinding(currentStatus, nextStatus) {
		reopenedCount++
	}
	finding.Status = normalizedNext
	finding.ReopenedCount = reopenedCount
	finding = risk.ApplyTemporalSignals(finding, now)

	updatedPayload, err := json.Marshal(finding)
	if err != nil {
		return models.CanonicalFinding{}, fmt.Errorf("marshal stored finding for status update: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE normalized_findings
		SET finding_json = $3,
		    current_status = $4,
		    reopened_count = $5,
		    updated_at = $6
		WHERE tenant_id = $1
		  AND finding_id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(findingID), updatedPayload, normalizedNext, reopenedCount, now)
	if err != nil {
		return models.CanonicalFinding{}, fmt.Errorf("update stored finding status: %w", err)
	}

	return finding, nil
}

func scanRemediationActivity(scanner interface{ Scan(dest ...any) error }) (models.RemediationActivity, error) {
	var item models.RemediationActivity
	var metadataJSON []byte
	err := scanner.Scan(&item.ID, &item.TenantID, &item.RemediationID, &item.EventType, &item.Actor, &item.Comment, &metadataJSON, &item.CreatedAt)
	if err != nil {
		return models.RemediationActivity{}, fmt.Errorf("scan remediation activity: %w", err)
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &item.Metadata); err != nil {
			return models.RemediationActivity{}, fmt.Errorf("decode remediation activity metadata: %w", err)
		}
	}
	return item, nil
}

func scanRemediationVerification(scanner interface{ Scan(dest ...any) error }) (models.RemediationVerification, error) {
	var item models.RemediationVerification
	err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.RemediationID,
		&item.FindingID,
		&item.ScanJobID,
		&item.Status,
		&item.Outcome,
		&item.RequestedBy,
		&item.VerifiedBy,
		&item.Notes,
		&item.RequestedAt,
		&item.VerifiedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.RemediationVerification{}, fmt.Errorf("scan remediation verification: %w", err)
	}
	return item, nil
}

func scanRemediationException(scanner interface{ Scan(dest ...any) error }) (models.RemediationException, error) {
	var item models.RemediationException
	err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.RemediationID,
		&item.FindingID,
		&item.Reason,
		&item.Reduction,
		&item.Notes,
		&item.Status,
		&item.RequestedBy,
		&item.DecidedBy,
		&item.ExpiresAt,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.DecidedAt,
	)
	if err != nil {
		return models.RemediationException{}, fmt.Errorf("scan remediation exception: %w", err)
	}
	return item, nil
}

func scanRemediationTicketLink(scanner interface{ Scan(dest ...any) error }) (models.RemediationTicketLink, error) {
	var item models.RemediationTicketLink
	err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.RemediationID,
		&item.Provider,
		&item.ExternalID,
		&item.Title,
		&item.URL,
		&item.Status,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.RemediationTicketLink{}, fmt.Errorf("scan remediation ticket link: %w", err)
	}
	return item, nil
}

func normalizeVerificationOutcome(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "passed", "pass":
		return "passed"
	case "failed", "fail":
		return "failed"
	default:
		return ""
	}
}

func firstNonEmptyFindingTool(finding models.CanonicalFinding) string {
	if strings.TrimSpace(finding.Scanner.AdapterID) != "" {
		return finding.Scanner.AdapterID
	}
	return finding.Source.Tool
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
