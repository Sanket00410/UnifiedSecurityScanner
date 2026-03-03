package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListRemediationAssignmentRequestsForTenant(ctx context.Context, organizationID string, remediationID string, limit int) ([]models.RemediationAssignmentRequest, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, remediation_id, finding_id, requested_by, requested_owner, reason, status, decided_by, created_at, updated_at, decided_at
		FROM remediation_assignment_requests
		WHERE tenant_id = $1
		  AND remediation_id = $2
		ORDER BY updated_at DESC
		LIMIT $3
	`, strings.TrimSpace(organizationID), strings.TrimSpace(remediationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list remediation assignment requests: %w", err)
	}
	defer rows.Close()

	out := make([]models.RemediationAssignmentRequest, 0, limit)
	for rows.Next() {
		item, err := scanRemediationAssignmentRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate remediation assignment requests: %w", err)
	}

	return out, nil
}

func (s *Store) CreateRemediationAssignmentRequestForTenant(ctx context.Context, organizationID string, remediationID string, actor string, request models.CreateRemediationAssignmentRequest) (models.RemediationAssignmentRequest, error) {
	if strings.TrimSpace(request.RequestedOwner) == "" {
		return models.RemediationAssignmentRequest{}, ErrInvalidAssignmentDecision
	}

	remediation, found, err := s.GetRemediationForTenant(ctx, organizationID, remediationID)
	if err != nil {
		return models.RemediationAssignmentRequest{}, err
	}
	if !found {
		return models.RemediationAssignmentRequest{}, ErrTaskNotFound
	}

	now := time.Now().UTC()
	item := models.RemediationAssignmentRequest{
		ID:             nextAssignmentRequestID(),
		TenantID:       strings.TrimSpace(organizationID),
		RemediationID:  remediation.ID,
		FindingID:      remediation.FindingID,
		RequestedBy:    strings.TrimSpace(actor),
		RequestedOwner: strings.TrimSpace(request.RequestedOwner),
		Reason:         strings.TrimSpace(request.Reason),
		Status:         "pending",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationAssignmentRequest{}, fmt.Errorf("begin remediation assignment tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO remediation_assignment_requests (
			id, tenant_id, remediation_id, finding_id, requested_by, requested_owner, reason, status, decided_by, created_at, updated_at, decided_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, '', $9, $9, NULL
		)
	`, item.ID, item.TenantID, item.RemediationID, item.FindingID, item.RequestedBy, item.RequestedOwner, item.Reason, item.Status, now)
	if err != nil {
		return models.RemediationAssignmentRequest{}, fmt.Errorf("insert remediation assignment request: %w", err)
	}

	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      item.TenantID,
		RemediationID: item.RemediationID,
		EventType:     "assignment_requested",
		Actor:         item.RequestedBy,
		Comment:       item.Reason,
		Metadata: map[string]any{
			"assignment_request_id": item.ID,
			"requested_owner":       item.RequestedOwner,
		},
		CreatedAt: now,
	}); err != nil {
		return models.RemediationAssignmentRequest{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationAssignmentRequest{}, fmt.Errorf("commit remediation assignment tx: %w", err)
	}

	return item, nil
}

func (s *Store) DecideRemediationAssignmentRequestForTenant(ctx context.Context, organizationID string, requestID string, approved bool, actor string, reason string) (models.RemediationAssignmentRequest, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationAssignmentRequest{}, false, fmt.Errorf("begin assignment decision tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var item models.RemediationAssignmentRequest
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, remediation_id, finding_id, requested_by, requested_owner, reason, status, decided_by, created_at, updated_at, decided_at
		FROM remediation_assignment_requests
		WHERE tenant_id = $1
		  AND id = $2
		FOR UPDATE
	`, strings.TrimSpace(organizationID), strings.TrimSpace(requestID)).Scan(
		&item.ID,
		&item.TenantID,
		&item.RemediationID,
		&item.FindingID,
		&item.RequestedBy,
		&item.RequestedOwner,
		&item.Reason,
		&item.Status,
		&item.DecidedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.DecidedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.RemediationAssignmentRequest{}, false, nil
		}
		return models.RemediationAssignmentRequest{}, false, fmt.Errorf("load assignment request: %w", err)
	}

	if strings.ToLower(strings.TrimSpace(item.Status)) != "pending" {
		return models.RemediationAssignmentRequest{}, false, ErrInvalidAssignmentDecision
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
		if strings.TrimSpace(item.Reason) == "" {
			item.Reason = strings.TrimSpace(reason)
		} else {
			item.Reason = item.Reason + "\n" + strings.TrimSpace(reason)
		}
	}

	_, err = tx.Exec(ctx, `
		UPDATE remediation_assignment_requests
		SET status = $2,
		    reason = $3,
		    decided_by = $4,
		    decided_at = $5,
		    updated_at = $5
		WHERE id = $1
	`, item.ID, item.Status, item.Reason, item.DecidedBy, now)
	if err != nil {
		return models.RemediationAssignmentRequest{}, false, fmt.Errorf("update assignment request: %w", err)
	}

	if approved {
		_, err = tx.Exec(ctx, `
			UPDATE remediation_actions
			SET owner = $2,
			    updated_at = $3
			WHERE tenant_id = $1
			  AND id = $4
		`, item.TenantID, item.RequestedOwner, now, item.RemediationID)
		if err != nil {
			return models.RemediationAssignmentRequest{}, false, fmt.Errorf("update remediation owner from assignment request: %w", err)
		}
	}

	eventType := "assignment_denied"
	if approved {
		eventType = "assignment_approved"
	}
	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      item.TenantID,
		RemediationID: item.RemediationID,
		EventType:     eventType,
		Actor:         item.DecidedBy,
		Comment:       strings.TrimSpace(reason),
		Metadata: map[string]any{
			"assignment_request_id": item.ID,
			"requested_owner":       item.RequestedOwner,
			"status":                item.Status,
		},
		CreatedAt: now,
	}); err != nil {
		return models.RemediationAssignmentRequest{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationAssignmentRequest{}, false, fmt.Errorf("commit assignment decision tx: %w", err)
	}

	return item, true, nil
}

func (s *Store) SyncRemediationTicketLinkForTenant(ctx context.Context, organizationID string, remediationID string, ticketID string, request models.SyncRemediationTicketLinkRequest) (models.RemediationTicketLink, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.RemediationTicketLink{}, false, fmt.Errorf("begin ticket sync tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var item models.RemediationTicketLink
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, remediation_id, provider, external_id, title, url, status, created_at, updated_at
		FROM remediation_ticket_links
		WHERE tenant_id = $1
		  AND remediation_id = $2
		  AND id = $3
		FOR UPDATE
	`, strings.TrimSpace(organizationID), strings.TrimSpace(remediationID), strings.TrimSpace(ticketID)).Scan(
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
		if isNoRows(err) {
			return models.RemediationTicketLink{}, false, nil
		}
		return models.RemediationTicketLink{}, false, fmt.Errorf("load remediation ticket for sync: %w", err)
	}

	if strings.TrimSpace(request.Title) != "" {
		item.Title = strings.TrimSpace(request.Title)
	}
	if strings.TrimSpace(request.URL) != "" {
		item.URL = strings.TrimSpace(request.URL)
	}
	if strings.TrimSpace(request.Status) != "" {
		item.Status = strings.ToLower(strings.TrimSpace(request.Status))
	}
	item.UpdatedAt = time.Now().UTC()

	_, err = tx.Exec(ctx, `
		UPDATE remediation_ticket_links
		SET title = $2,
		    url = $3,
		    status = $4,
		    updated_at = $5
		WHERE id = $1
	`, item.ID, item.Title, item.URL, item.Status, item.UpdatedAt)
	if err != nil {
		return models.RemediationTicketLink{}, false, fmt.Errorf("update remediation ticket link: %w", err)
	}

	if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
		ID:            nextActivityID(),
		TenantID:      item.TenantID,
		RemediationID: item.RemediationID,
		EventType:     "ticket_synced",
		Metadata: map[string]any{
			"ticket_id":     item.ID,
			"provider":      item.Provider,
			"external_id":   item.ExternalID,
			"ticket_status": item.Status,
			"ticket_url":    item.URL,
		},
		CreatedAt: item.UpdatedAt,
	}); err != nil {
		return models.RemediationTicketLink{}, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return models.RemediationTicketLink{}, false, fmt.Errorf("commit ticket sync tx: %w", err)
	}

	return item, true, nil
}

func (s *Store) ListNotificationEventsForTenant(ctx context.Context, organizationID string, limit int) ([]models.NotificationEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, remediation_id, finding_id, category, severity, channel, status, recipient, subject, body, acknowledged_by, created_at, updated_at, acknowledged_at
		FROM notification_events
		WHERE tenant_id = $1
		ORDER BY updated_at DESC
		LIMIT $2
	`, strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list notification events: %w", err)
	}
	defer rows.Close()

	out := make([]models.NotificationEvent, 0, limit)
	for rows.Next() {
		item, err := scanNotificationEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notification events: %w", err)
	}

	return out, nil
}

func (s *Store) AcknowledgeNotificationEventForTenant(ctx context.Context, organizationID string, notificationID string, actor string) (models.NotificationEvent, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.NotificationEvent{}, false, fmt.Errorf("begin notification ack tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var item models.NotificationEvent
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, remediation_id, finding_id, category, severity, channel, status, recipient, subject, body, acknowledged_by, created_at, updated_at, acknowledged_at
		FROM notification_events
		WHERE tenant_id = $1
		  AND id = $2
		FOR UPDATE
	`, strings.TrimSpace(organizationID), strings.TrimSpace(notificationID)).Scan(
		&item.ID,
		&item.TenantID,
		&item.RemediationID,
		&item.FindingID,
		&item.Category,
		&item.Severity,
		&item.Channel,
		&item.Status,
		&item.Recipient,
		&item.Subject,
		&item.Body,
		&item.AcknowledgedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.AcknowledgedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.NotificationEvent{}, false, nil
		}
		return models.NotificationEvent{}, false, fmt.Errorf("load notification event: %w", err)
	}

	now := time.Now().UTC()
	item.Status = "acknowledged"
	item.AcknowledgedBy = strings.TrimSpace(actor)
	item.AcknowledgedAt = &now
	item.UpdatedAt = now

	_, err = tx.Exec(ctx, `
		UPDATE notification_events
		SET status = $2,
		    acknowledged_by = $3,
		    acknowledged_at = $4,
		    updated_at = $4
		WHERE id = $1
	`, item.ID, item.Status, item.AcknowledgedBy, now)
	if err != nil {
		return models.NotificationEvent{}, false, fmt.Errorf("update notification event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return models.NotificationEvent{}, false, fmt.Errorf("commit notification ack tx: %w", err)
	}

	return item, true, nil
}

func (s *Store) SweepRemediationEscalationsForTenant(ctx context.Context, organizationID string, actor string) (models.NotificationSweepResult, error) {
	now := time.Now().UTC()
	rows, err := s.pool.Query(ctx, `
		SELECT id, finding_id, title, status, owner, due_at, notes, created_at, updated_at
		FROM remediation_actions
		WHERE tenant_id = $1
		  AND due_at IS NOT NULL
		  AND due_at < $2
		  AND status NOT IN ('verified', 'accepted_risk', 'closed')
		ORDER BY due_at ASC
	`, strings.TrimSpace(organizationID), now)
	if err != nil {
		return models.NotificationSweepResult{}, fmt.Errorf("query overdue remediations: %w", err)
	}
	defer rows.Close()

	result := models.NotificationSweepResult{
		Items: make([]models.NotificationEvent, 0),
	}

	for rows.Next() {
		var remediation models.RemediationAction
		if err := rows.Scan(
			&remediation.ID,
			&remediation.FindingID,
			&remediation.Title,
			&remediation.Status,
			&remediation.Owner,
			&remediation.DueAt,
			&remediation.Notes,
			&remediation.CreatedAt,
			&remediation.UpdatedAt,
		); err != nil {
			return models.NotificationSweepResult{}, fmt.Errorf("scan overdue remediation: %w", err)
		}

		if remediation.DueAt == nil {
			continue
		}

		severity := "medium"
		if now.Sub(remediation.DueAt.UTC()) >= 72*time.Hour {
			severity = "high"
		}

		recipient := strings.TrimSpace(remediation.Owner)
		if recipient == "" {
			recipient = "unassigned"
		}
		dedupKey := "sla_breach:" + remediation.ID
		subject := "SLA breach: " + remediation.Title
		body := fmt.Sprintf("Remediation %s is overdue and requires action.", remediation.ID)

		var notification models.NotificationEvent
		var created bool
		tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return models.NotificationSweepResult{}, fmt.Errorf("begin escalation tx: %w", err)
		}

		err = tx.QueryRow(ctx, `
			SELECT id, tenant_id, remediation_id, finding_id, category, severity, channel, status, recipient, subject, body, acknowledged_by, created_at, updated_at, acknowledged_at
			FROM notification_events
			WHERE tenant_id = $1
			  AND dedup_key = $2
			FOR UPDATE
		`, strings.TrimSpace(organizationID), dedupKey).Scan(
			&notification.ID,
			&notification.TenantID,
			&notification.RemediationID,
			&notification.FindingID,
			&notification.Category,
			&notification.Severity,
			&notification.Channel,
			&notification.Status,
			&notification.Recipient,
			&notification.Subject,
			&notification.Body,
			&notification.AcknowledgedBy,
			&notification.CreatedAt,
			&notification.UpdatedAt,
			&notification.AcknowledgedAt,
		)
		if err != nil && !isNoRows(err) {
			_ = tx.Rollback(ctx)
			return models.NotificationSweepResult{}, fmt.Errorf("load existing escalation notification: %w", err)
		}

		if isNoRows(err) {
			created = true
			notification = models.NotificationEvent{
				ID:            nextNotificationID(),
				TenantID:      strings.TrimSpace(organizationID),
				RemediationID: remediation.ID,
				FindingID:     remediation.FindingID,
				Category:      "sla_breach",
				Severity:      severity,
				Channel:       "in_app",
				Status:        "pending",
				Recipient:     recipient,
				Subject:       subject,
				Body:          body,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			_, err = tx.Exec(ctx, `
				INSERT INTO notification_events (
					id, tenant_id, remediation_id, finding_id, category, severity, channel, status, recipient, subject, body, dedup_key, acknowledged_by, created_at, updated_at, acknowledged_at
				) VALUES (
					$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, '', $13, $13, NULL
				)
			`, notification.ID, notification.TenantID, notification.RemediationID, notification.FindingID, notification.Category, notification.Severity, notification.Channel, notification.Status, notification.Recipient, notification.Subject, notification.Body, dedupKey, now)
			if err != nil {
				_ = tx.Rollback(ctx)
				return models.NotificationSweepResult{}, fmt.Errorf("insert escalation notification: %w", err)
			}
		} else {
			notification.Severity = severity
			notification.Recipient = recipient
			notification.Subject = subject
			notification.Body = body
			if notification.Status == "acknowledged" {
				notification.Status = "pending"
				notification.AcknowledgedAt = nil
				notification.AcknowledgedBy = ""
			}
			notification.UpdatedAt = now
			_, err = tx.Exec(ctx, `
				UPDATE notification_events
				SET severity = $2,
				    status = $3,
				    recipient = $4,
				    subject = $5,
				    body = $6,
				    acknowledged_by = $7,
				    acknowledged_at = $8,
				    updated_at = $9
				WHERE id = $1
			`, notification.ID, notification.Severity, notification.Status, notification.Recipient, notification.Subject, notification.Body, notification.AcknowledgedBy, notification.AcknowledgedAt, notification.UpdatedAt)
			if err != nil {
				_ = tx.Rollback(ctx)
				return models.NotificationSweepResult{}, fmt.Errorf("update escalation notification: %w", err)
			}
		}

		if err := insertRemediationActivityTx(ctx, tx, models.RemediationActivity{
			ID:            nextActivityID(),
			TenantID:      notification.TenantID,
			RemediationID: remediation.ID,
			EventType:     "sla_escalated",
			Actor:         strings.TrimSpace(actor),
			Metadata: map[string]any{
				"notification_id": notification.ID,
				"severity":        notification.Severity,
				"recipient":       notification.Recipient,
			},
			CreatedAt: now,
		}); err != nil {
			_ = tx.Rollback(ctx)
			return models.NotificationSweepResult{}, err
		}

		if err := tx.Commit(ctx); err != nil {
			return models.NotificationSweepResult{}, fmt.Errorf("commit escalation notification: %w", err)
		}

		if created {
			result.Created++
		}
		result.Items = append(result.Items, notification)
	}

	if err := rows.Err(); err != nil {
		return models.NotificationSweepResult{}, fmt.Errorf("iterate overdue remediations: %w", err)
	}

	return result, nil
}

func scanRemediationAssignmentRequest(scanner interface{ Scan(dest ...any) error }) (models.RemediationAssignmentRequest, error) {
	var item models.RemediationAssignmentRequest
	err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.RemediationID,
		&item.FindingID,
		&item.RequestedBy,
		&item.RequestedOwner,
		&item.Reason,
		&item.Status,
		&item.DecidedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.DecidedAt,
	)
	if err != nil {
		return models.RemediationAssignmentRequest{}, fmt.Errorf("scan remediation assignment request: %w", err)
	}
	return item, nil
}

func scanNotificationEvent(scanner interface{ Scan(dest ...any) error }) (models.NotificationEvent, error) {
	var item models.NotificationEvent
	err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.RemediationID,
		&item.FindingID,
		&item.Category,
		&item.Severity,
		&item.Channel,
		&item.Status,
		&item.Recipient,
		&item.Subject,
		&item.Body,
		&item.AcknowledgedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.AcknowledgedAt,
	)
	if err != nil {
		return models.NotificationEvent{}, fmt.Errorf("scan notification event: %w", err)
	}
	return item, nil
}
