package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"unifiedsecurityscanner/control-plane/internal/models"
)

type webhookIntegrationRecord struct {
	integration     models.WebhookIntegration
	secretEncrypted string
}

type webhookReplayCandidate struct {
	webhookID       string
	platformEventID string
	eventType       string
	attemptCount    int
}

const (
	defaultWebhookRetryMaxAttempts      = 3
	defaultWebhookRetryBaseDelaySeconds = 1
	defaultWebhookRetryMaxDelaySeconds  = 30
	minWebhookRetryMaxAttempts          = 1
	maxWebhookRetryMaxAttempts          = 10
	minWebhookRetryDelaySeconds         = 1
	maxWebhookRetryDelaySeconds         = 86400
)

func (s *Store) ListWebhookIntegrationsForTenant(ctx context.Context, tenantID string, status string, eventType string, limit int) ([]models.WebhookIntegration, error) {
	tenantID = strings.TrimSpace(tenantID)
	status = normalizeWebhookIntegrationStatus(status)
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, endpoint_url, event_types_json, headers_json, status,
		       retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds,
		       secret_encrypted, last_attempt_at, last_success_at, created_by, updated_by, created_at, updated_at
		FROM webhook_integrations
		WHERE tenant_id = $1
		  AND ($2 = '' OR status = $2)
		ORDER BY updated_at DESC, id DESC
		LIMIT $3
	`, tenantID, status, limit)
	if err != nil {
		return nil, fmt.Errorf("list webhook integrations: %w", err)
	}
	defer rows.Close()

	items := make([]models.WebhookIntegration, 0, limit)
	for rows.Next() {
		record, err := scanWebhookIntegrationRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan webhook integration row: %w", err)
		}
		if eventType != "" && !webhookAcceptsEvent(record.integration.EventTypes, eventType) {
			continue
		}
		items = append(items, record.integration)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhook integration rows: %w", err)
	}
	return items, nil
}

func (s *Store) GetWebhookIntegrationForTenant(ctx context.Context, tenantID string, webhookID string) (models.WebhookIntegration, bool, error) {
	record, found, err := s.getWebhookIntegrationRecordForTenant(ctx, tenantID, webhookID)
	if err != nil || !found {
		return models.WebhookIntegration{}, found, err
	}
	return record.integration, true, nil
}

func (s *Store) CreateWebhookIntegrationForTenant(ctx context.Context, tenantID string, actor string, request models.CreateWebhookIntegrationRequest) (models.WebhookIntegration, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	name := strings.TrimSpace(request.Name)
	endpointURL := strings.TrimSpace(request.EndpointURL)
	if name == "" || endpointURL == "" {
		return models.WebhookIntegration{}, fmt.Errorf("name and endpoint_url are required")
	}
	if err := validateWebhookEndpointURL(endpointURL); err != nil {
		return models.WebhookIntegration{}, err
	}

	status := normalizeWebhookIntegrationStatus(request.Status)
	if status == "" {
		status = "active"
	}
	eventTypes := normalizeWebhookEventTypes(request.EventTypes)
	headers := sanitizeWebhookHeaders(request.Headers)
	retryMaxAttempts, retryBaseDelaySeconds, retryMaxDelaySeconds, err := normalizeWebhookRetryPolicy(
		request.RetryMaxAttempts,
		request.RetryBaseDelaySeconds,
		request.RetryMaxDelaySeconds,
	)
	if err != nil {
		return models.WebhookIntegration{}, err
	}

	now := time.Now().UTC()
	item := models.WebhookIntegration{
		ID:                    nextWebhookIntegrationID(),
		TenantID:              tenantID,
		Name:                  name,
		EndpointURL:           endpointURL,
		EventTypes:            eventTypes,
		Headers:               headers,
		Status:                status,
		RetryMaxAttempts:      retryMaxAttempts,
		RetryBaseDelaySeconds: retryBaseDelaySeconds,
		RetryMaxDelaySeconds:  retryMaxDelaySeconds,
		SecretSet:             strings.TrimSpace(request.Secret) != "",
		CreatedBy:             actor,
		UpdatedBy:             actor,
		CreatedAt:             now,
		UpdatedAt:             now,
		LastAttemptAt:         nil,
		LastSuccessAt:         nil,
	}
	eventTypesJSON, err := json.Marshal(item.EventTypes)
	if err != nil {
		return models.WebhookIntegration{}, fmt.Errorf("marshal webhook event types: %w", err)
	}
	headersJSON, err := json.Marshal(item.Headers)
	if err != nil {
		return models.WebhookIntegration{}, fmt.Errorf("marshal webhook headers: %w", err)
	}

	secretEncrypted, err := s.encryptIngestionWebhookSecret(item.TenantID, item.ID, "webhook_integration", strings.TrimSpace(request.Secret))
	if err != nil {
		return models.WebhookIntegration{}, fmt.Errorf("encrypt webhook secret: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO webhook_integrations (
			id, tenant_id, name, endpoint_url, event_types_json, headers_json, status,
			retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds, secret_encrypted,
			last_attempt_at, last_success_at, created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11,
			NULL, NULL, $12, $12, $13, $13
		)
		RETURNING id, tenant_id, name, endpoint_url, event_types_json, headers_json, status,
		          retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds,
		          secret_encrypted, last_attempt_at, last_success_at, created_by, updated_by, created_at, updated_at
	`, item.ID, item.TenantID, item.Name, item.EndpointURL, eventTypesJSON, headersJSON, item.Status,
		item.RetryMaxAttempts, item.RetryBaseDelaySeconds, item.RetryMaxDelaySeconds, secretEncrypted, item.CreatedBy, item.CreatedAt)

	record, err := scanWebhookIntegrationRecord(row)
	if err != nil {
		return models.WebhookIntegration{}, fmt.Errorf("create webhook integration: %w", err)
	}
	return record.integration, nil
}

func (s *Store) UpdateWebhookIntegrationForTenant(ctx context.Context, tenantID string, webhookID string, actor string, request models.UpdateWebhookIntegrationRequest) (models.WebhookIntegration, bool, error) {
	record, found, err := s.getWebhookIntegrationRecordForTenant(ctx, tenantID, webhookID)
	if err != nil || !found {
		return models.WebhookIntegration{}, found, err
	}

	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	item := record.integration
	if value := strings.TrimSpace(request.Name); value != "" {
		item.Name = value
	}
	if value := strings.TrimSpace(request.EndpointURL); value != "" {
		if err := validateWebhookEndpointURL(value); err != nil {
			return models.WebhookIntegration{}, true, err
		}
		item.EndpointURL = value
	}
	if request.EventTypes != nil {
		item.EventTypes = normalizeWebhookEventTypes(request.EventTypes)
	}
	if request.Headers != nil {
		item.Headers = sanitizeWebhookHeaders(request.Headers)
	}
	if value := normalizeWebhookIntegrationStatus(request.Status); value != "" {
		item.Status = value
	}
	nextRetryMaxAttempts := item.RetryMaxAttempts
	if request.RetryMaxAttempts > 0 {
		nextRetryMaxAttempts = request.RetryMaxAttempts
	}
	nextRetryBaseDelaySeconds := item.RetryBaseDelaySeconds
	if request.RetryBaseDelaySeconds > 0 {
		nextRetryBaseDelaySeconds = request.RetryBaseDelaySeconds
	}
	nextRetryMaxDelaySeconds := item.RetryMaxDelaySeconds
	if request.RetryMaxDelaySeconds > 0 {
		nextRetryMaxDelaySeconds = request.RetryMaxDelaySeconds
	}
	nextRetryMaxAttempts, nextRetryBaseDelaySeconds, nextRetryMaxDelaySeconds, err = normalizeWebhookRetryPolicy(
		nextRetryMaxAttempts,
		nextRetryBaseDelaySeconds,
		nextRetryMaxDelaySeconds,
	)
	if err != nil {
		return models.WebhookIntegration{}, true, err
	}
	item.RetryMaxAttempts = nextRetryMaxAttempts
	item.RetryBaseDelaySeconds = nextRetryBaseDelaySeconds
	item.RetryMaxDelaySeconds = nextRetryMaxDelaySeconds
	item.UpdatedBy = actor
	item.UpdatedAt = time.Now().UTC()

	secretEncrypted := record.secretEncrypted
	if strings.TrimSpace(request.Secret) != "" {
		secretEncrypted, err = s.encryptIngestionWebhookSecret(item.TenantID, item.ID, "webhook_integration", strings.TrimSpace(request.Secret))
		if err != nil {
			return models.WebhookIntegration{}, true, fmt.Errorf("encrypt webhook secret: %w", err)
		}
		item.SecretSet = true
	}
	eventTypesJSON, err := json.Marshal(item.EventTypes)
	if err != nil {
		return models.WebhookIntegration{}, true, fmt.Errorf("marshal webhook event types: %w", err)
	}
	headersJSON, err := json.Marshal(item.Headers)
	if err != nil {
		return models.WebhookIntegration{}, true, fmt.Errorf("marshal webhook headers: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE webhook_integrations
		SET name = $3,
		    endpoint_url = $4,
		    event_types_json = $5,
		    headers_json = $6,
		    status = $7,
		    retry_max_attempts = $8,
		    retry_base_delay_seconds = $9,
		    retry_max_delay_seconds = $10,
		    secret_encrypted = $11,
		    updated_by = $12,
		    updated_at = $13
		WHERE tenant_id = $1
		  AND id = $2
		RETURNING id, tenant_id, name, endpoint_url, event_types_json, headers_json, status,
		          retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds,
		          secret_encrypted, last_attempt_at, last_success_at, created_by, updated_by, created_at, updated_at
	`, item.TenantID, item.ID, item.Name, item.EndpointURL, eventTypesJSON, headersJSON, item.Status,
		item.RetryMaxAttempts, item.RetryBaseDelaySeconds, item.RetryMaxDelaySeconds, secretEncrypted, item.UpdatedBy, item.UpdatedAt)
	updatedRecord, err := scanWebhookIntegrationRecord(row)
	if err != nil {
		if isNoRows(err) {
			return models.WebhookIntegration{}, false, nil
		}
		return models.WebhookIntegration{}, true, fmt.Errorf("update webhook integration: %w", err)
	}
	return updatedRecord.integration, true, nil
}

func (s *Store) ListWebhookDeliveriesForTenant(ctx context.Context, tenantID string, webhookID string, status string, limit int) ([]models.WebhookDelivery, error) {
	tenantID = strings.TrimSpace(tenantID)
	webhookID = strings.TrimSpace(webhookID)
	status = normalizeWebhookDeliveryStatus(status)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, webhook_id, platform_event_id, event_type, status, attempt_count,
		       response_status, response_body, error_message, attempted_at, next_attempt_at, delivered_at, dead_lettered_at, created_at
		FROM webhook_deliveries
		WHERE tenant_id = $1
		  AND ($2 = '' OR webhook_id = $2)
		  AND ($3 = '' OR status = $3)
		ORDER BY attempted_at DESC, id DESC
		LIMIT $4
	`, tenantID, webhookID, status, limit)
	if err != nil {
		return nil, fmt.Errorf("list webhook deliveries: %w", err)
	}
	defer rows.Close()

	items := make([]models.WebhookDelivery, 0, limit)
	for rows.Next() {
		item, err := scanWebhookDelivery(rows)
		if err != nil {
			return nil, fmt.Errorf("scan webhook delivery row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhook delivery rows: %w", err)
	}
	return items, nil
}

func (s *Store) DispatchWebhookDeliveriesForTenant(ctx context.Context, tenantID string, actor string, request models.DispatchWebhookDeliveriesRequest) (models.DispatchWebhookDeliveriesResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	limit := request.Limit
	if limit <= 0 || limit > 2000 {
		limit = 200
	}

	webhookID := strings.TrimSpace(request.WebhookID)
	webhooks, err := s.listWebhookIntegrationRecordsForDispatch(ctx, tenantID, webhookID)
	if err != nil {
		return models.DispatchWebhookDeliveriesResult{}, err
	}
	if webhookID != "" && len(webhooks) == 0 {
		return models.DispatchWebhookDeliveriesResult{}, ErrWebhookIntegrationNotFound
	}
	if len(webhooks) == 0 {
		return models.DispatchWebhookDeliveriesResult{ByWebhook: map[string]int64{}}, nil
	}

	eventType := strings.ToLower(strings.TrimSpace(request.EventType))
	events, err := s.ListPlatformEventsForTenant(ctx, tenantID, eventType, limit)
	if err != nil {
		return models.DispatchWebhookDeliveriesResult{}, err
	}

	result := models.DispatchWebhookDeliveriesResult{
		ByWebhook: map[string]int64{},
	}
	if len(events) == 0 {
		return result, nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	now := time.Now().UTC()
	for _, event := range events {
		for _, webhook := range webhooks {
			if !webhookAcceptsEvent(webhook.integration.EventTypes, event.EventType) {
				result.Skipped++
				continue
			}

			attemptCount := 1
			if !request.Replay {
				existing, found, err := s.getLatestWebhookDeliveryForEvent(ctx, tenantID, webhook.integration.ID, event.ID)
				if err != nil {
					return models.DispatchWebhookDeliveriesResult{}, err
				}

				if found {
					switch existing.Status {
					case "delivered", "dead_letter":
						result.Skipped++
						continue
					case "scheduled_retry":
						if existing.NextAttemptAt != nil && existing.NextAttemptAt.After(now) {
							result.Skipped++
							continue
						}
					}
					if existing.AttemptCount >= webhook.integration.RetryMaxAttempts {
						result.Skipped++
						continue
					}
					attemptCount = existing.AttemptCount + 1
				}
			} else {
				existing, found, err := s.getLatestWebhookDeliveryForEvent(ctx, tenantID, webhook.integration.ID, event.ID)
				if err != nil {
					return models.DispatchWebhookDeliveriesResult{}, err
				}
				if found {
					attemptCount = existing.AttemptCount + 1
				}
			}

			attemptedAt := time.Now().UTC()
			result.Attempted++
			delivery := models.WebhookDelivery{
				ID:              nextWebhookDeliveryID(),
				TenantID:        tenantID,
				WebhookID:       webhook.integration.ID,
				PlatformEventID: strings.TrimSpace(event.ID),
				EventType:       strings.TrimSpace(event.EventType),
				Status:          "failed",
				AttemptCount:    attemptCount,
				AttemptedAt:     attemptedAt,
				CreatedAt:       attemptedAt,
			}

			delivered, responseStatus, responseBody, errMessage := s.sendWebhookDelivery(ctx, client, webhook, event, delivery.ID)
			delivery.ResponseStatus = responseStatus
			delivery.ResponseBody = truncateWebhookText(responseBody, 2048)
			delivery.ErrorMessage = truncateWebhookText(errMessage, 1024)
			if delivered {
				successAt := time.Now().UTC()
				delivery.Status = "delivered"
				delivery.DeliveredAt = &successAt
				delivery.NextAttemptAt = nil
				delivery.DeadLetteredAt = nil
			} else if request.Replay {
				delivery.Status = "failed"
			} else if attemptCount >= webhook.integration.RetryMaxAttempts {
				deadLetteredAt := time.Now().UTC()
				delivery.Status = "dead_letter"
				delivery.DeadLetteredAt = &deadLetteredAt
			} else {
				nextAttempt := attemptedAt.Add(webhookRetryDelay(
					attemptCount,
					webhook.integration.RetryBaseDelaySeconds,
					webhook.integration.RetryMaxDelaySeconds,
				))
				delivery.Status = "scheduled_retry"
				delivery.NextAttemptAt = &nextAttempt
			}

			if err := s.insertWebhookDelivery(ctx, delivery); err != nil {
				return models.DispatchWebhookDeliveriesResult{}, err
			}
			if err := s.updateWebhookDeliveryStatusSummary(ctx, tenantID, webhook.integration.ID, attemptedAt, delivery.DeliveredAt); err != nil {
				return models.DispatchWebhookDeliveriesResult{}, err
			}

			if delivered {
				result.Delivered++
				result.ByWebhook[webhook.integration.ID]++
			} else {
				result.Failed++
			}
		}
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "webhook.dispatch.completed",
		SourceService: "control-plane",
		AggregateType: "webhook_dispatch",
		AggregateID:   actor,
		Payload: map[string]any{
			"attempted":  result.Attempted,
			"delivered":  result.Delivered,
			"failed":     result.Failed,
			"skipped":    result.Skipped,
			"event_type": eventType,
		},
		CreatedAt: time.Now().UTC(),
	})

	return result, nil
}

func (s *Store) DispatchWebhookDeliveriesForAllTenants(ctx context.Context, actor string, limitPerTenant int) (models.DispatchWebhookDeliveriesSweepResult, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	if limitPerTenant <= 0 || limitPerTenant > 2000 {
		limitPerTenant = 200
	}

	tenantIDs, err := s.listActiveWebhookTenantIDs(ctx)
	if err != nil {
		return models.DispatchWebhookDeliveriesSweepResult{}, err
	}

	out := models.DispatchWebhookDeliveriesSweepResult{
		ByTenant: map[string]models.DispatchTenantSummary{},
	}

	for _, tenantID := range tenantIDs {
		result, err := s.DispatchWebhookDeliveriesForTenant(ctx, tenantID, actor, models.DispatchWebhookDeliveriesRequest{
			Limit: limitPerTenant,
		})
		if err != nil {
			return models.DispatchWebhookDeliveriesSweepResult{}, err
		}

		summary := models.DispatchTenantSummary{
			Attempted: result.Attempted,
			Delivered: result.Delivered,
			Failed:    result.Failed,
			Skipped:   result.Skipped,
		}
		out.ByTenant[tenantID] = summary
		out.TenantsEvaluated++
		out.Attempted += result.Attempted
		out.Delivered += result.Delivered
		out.Failed += result.Failed
		out.Skipped += result.Skipped
	}

	return out, nil
}

func (s *Store) ListWebhookDeliveryMetricsForTenant(
	ctx context.Context,
	tenantID string,
	webhookID string,
	eventType string,
	since *time.Time,
	until *time.Time,
	limit int,
) (models.WebhookDeliveryMetricsResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	webhookID = strings.TrimSpace(webhookID)
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT webhook_id,
		       COUNT(*) AS total_attempts,
		       COUNT(*) FILTER (WHERE status = 'delivered') AS delivered_attempts,
		       COUNT(*) FILTER (WHERE status = 'failed') AS failed_attempts,
		       COUNT(*) FILTER (WHERE status = 'scheduled_retry') AS scheduled_retry_attempts,
		       COUNT(*) FILTER (WHERE status = 'dead_letter') AS dead_letter_attempts,
		       MAX(attempted_at) AS last_attempt_at,
		       MAX(delivered_at) AS last_delivered_at
		FROM webhook_deliveries
		WHERE tenant_id = $1
		  AND ($2 = '' OR webhook_id = $2)
		  AND ($3 = '' OR event_type = $3)
		  AND ($4::timestamptz IS NULL OR attempted_at >= $4)
		  AND ($5::timestamptz IS NULL OR attempted_at <= $5)
		GROUP BY webhook_id
		ORDER BY total_attempts DESC, webhook_id ASC
		LIMIT $6
	`, tenantID, webhookID, eventType, since, until, limit)
	if err != nil {
		return models.WebhookDeliveryMetricsResult{}, fmt.Errorf("list webhook delivery metrics: %w", err)
	}
	defer rows.Close()

	out := models.WebhookDeliveryMetricsResult{
		Summary: models.WebhookDeliveryMetricsSummary{},
		Items:   make([]models.WebhookDeliveryMetrics, 0, limit),
	}

	for rows.Next() {
		var item models.WebhookDeliveryMetrics
		if err := rows.Scan(
			&item.WebhookID,
			&item.TotalAttempts,
			&item.DeliveredAttempts,
			&item.FailedAttempts,
			&item.ScheduledRetryAttempts,
			&item.DeadLetterAttempts,
			&item.LastAttemptAt,
			&item.LastDeliveredAt,
		); err != nil {
			return models.WebhookDeliveryMetricsResult{}, fmt.Errorf("scan webhook delivery metrics: %w", err)
		}
		item.SuccessRate = computeWebhookSuccessRate(item.DeliveredAttempts, item.TotalAttempts)
		out.Items = append(out.Items, item)

		out.Summary.TotalAttempts += item.TotalAttempts
		out.Summary.DeliveredAttempts += item.DeliveredAttempts
		out.Summary.FailedAttempts += item.FailedAttempts
		out.Summary.ScheduledRetryAttempts += item.ScheduledRetryAttempts
		out.Summary.DeadLetterAttempts += item.DeadLetterAttempts
	}
	if err := rows.Err(); err != nil {
		return models.WebhookDeliveryMetricsResult{}, fmt.Errorf("iterate webhook delivery metrics: %w", err)
	}
	out.Summary.SuccessRate = computeWebhookSuccessRate(out.Summary.DeliveredAttempts, out.Summary.TotalAttempts)
	return out, nil
}

func (s *Store) ReplayDeadLetterWebhookDeliveriesForTenant(
	ctx context.Context,
	tenantID string,
	actor string,
	request models.ReplayDeadLetterWebhookDeliveriesRequest,
) (models.ReplayDeadLetterWebhookDeliveriesResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	limit := request.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	webhookID := strings.TrimSpace(request.WebhookID)
	eventType := strings.ToLower(strings.TrimSpace(request.EventType))
	candidates, err := s.listDeadLetterReplayCandidatesForTenant(ctx, tenantID, webhookID, eventType, request.Since, request.Until, limit)
	if err != nil {
		return models.ReplayDeadLetterWebhookDeliveriesResult{}, err
	}

	result := models.ReplayDeadLetterWebhookDeliveriesResult{
		Candidates: int64(len(candidates)),
	}
	if len(candidates) == 0 {
		return result, nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, candidate := range candidates {
		webhook, found, err := s.getWebhookIntegrationRecordForTenant(ctx, tenantID, candidate.webhookID)
		if err != nil {
			return models.ReplayDeadLetterWebhookDeliveriesResult{}, err
		}
		if !found {
			result.Skipped++
			continue
		}
		if strings.TrimSpace(webhook.integration.Status) != "active" {
			result.Skipped++
			continue
		}
		if !webhookAcceptsEvent(webhook.integration.EventTypes, candidate.eventType) {
			result.Skipped++
			continue
		}

		event, found, err := s.getPlatformEventForTenant(ctx, tenantID, candidate.platformEventID)
		if err != nil {
			return models.ReplayDeadLetterWebhookDeliveriesResult{}, err
		}
		if !found {
			result.Skipped++
			continue
		}

		attemptCount := candidate.attemptCount + 1
		attemptedAt := time.Now().UTC()
		delivery := models.WebhookDelivery{
			ID:              nextWebhookDeliveryID(),
			TenantID:        tenantID,
			WebhookID:       candidate.webhookID,
			PlatformEventID: candidate.platformEventID,
			EventType:       candidate.eventType,
			Status:          "failed",
			AttemptCount:    attemptCount,
			AttemptedAt:     attemptedAt,
			CreatedAt:       attemptedAt,
		}

		delivered, responseStatus, responseBody, errMessage := s.sendWebhookDelivery(ctx, client, webhook, event, delivery.ID)
		delivery.ResponseStatus = responseStatus
		delivery.ResponseBody = truncateWebhookText(responseBody, 2048)
		delivery.ErrorMessage = truncateWebhookText(errMessage, 1024)

		result.Attempted++
		if delivered {
			deliveredAt := time.Now().UTC()
			delivery.Status = "delivered"
			delivery.DeliveredAt = &deliveredAt
			result.Delivered++
		} else if attemptCount >= webhook.integration.RetryMaxAttempts {
			deadLetteredAt := time.Now().UTC()
			delivery.Status = "dead_letter"
			delivery.DeadLetteredAt = &deadLetteredAt
			result.DeadLettered++
			result.Failed++
		} else {
			nextAttemptAt := attemptedAt.Add(webhookRetryDelay(
				attemptCount,
				webhook.integration.RetryBaseDelaySeconds,
				webhook.integration.RetryMaxDelaySeconds,
			))
			delivery.Status = "scheduled_retry"
			delivery.NextAttemptAt = &nextAttemptAt
			result.Requeued++
			result.Failed++
		}

		if err := s.insertWebhookDelivery(ctx, delivery); err != nil {
			return models.ReplayDeadLetterWebhookDeliveriesResult{}, err
		}
		if err := s.updateWebhookDeliveryStatusSummary(ctx, tenantID, webhook.integration.ID, attemptedAt, delivery.DeliveredAt); err != nil {
			return models.ReplayDeadLetterWebhookDeliveriesResult{}, err
		}
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "webhook.dead_letter.replay.completed",
		SourceService: "control-plane",
		AggregateType: "webhook_dead_letter_replay",
		AggregateID:   actor,
		Payload: map[string]any{
			"candidates":    result.Candidates,
			"attempted":     result.Attempted,
			"delivered":     result.Delivered,
			"failed":        result.Failed,
			"requeued":      result.Requeued,
			"dead_lettered": result.DeadLettered,
			"skipped":       result.Skipped,
		},
		CreatedAt: time.Now().UTC(),
	})

	return result, nil
}

func (s *Store) listActiveWebhookTenantIDs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT tenant_id
		FROM webhook_integrations
		WHERE status = 'active'
		ORDER BY tenant_id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list active webhook tenant ids: %w", err)
	}
	defer rows.Close()

	out := make([]string, 0)
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, fmt.Errorf("scan active webhook tenant id: %w", err)
		}
		tenantID = strings.TrimSpace(tenantID)
		if tenantID == "" {
			continue
		}
		out = append(out, tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active webhook tenant ids: %w", err)
	}
	return out, nil
}

func (s *Store) getLatestWebhookDeliveryForEvent(ctx context.Context, tenantID string, webhookID string, platformEventID string) (models.WebhookDelivery, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, webhook_id, platform_event_id, event_type, status, attempt_count,
		       response_status, response_body, error_message, attempted_at, next_attempt_at, delivered_at, dead_lettered_at, created_at
		FROM webhook_deliveries
		WHERE tenant_id = $1
		  AND webhook_id = $2
		  AND platform_event_id = $3
		ORDER BY attempted_at DESC, id DESC
		LIMIT 1
	`, strings.TrimSpace(tenantID), strings.TrimSpace(webhookID), strings.TrimSpace(platformEventID))
	item, err := scanWebhookDelivery(row)
	if err != nil {
		if isNoRows(err) {
			return models.WebhookDelivery{}, false, nil
		}
		return models.WebhookDelivery{}, false, fmt.Errorf("get latest webhook delivery: %w", err)
	}
	return item, true, nil
}

func (s *Store) listDeadLetterReplayCandidatesForTenant(
	ctx context.Context,
	tenantID string,
	webhookID string,
	eventType string,
	since *time.Time,
	until *time.Time,
	limit int,
) ([]webhookReplayCandidate, error) {
	rows, err := s.pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (webhook_id, platform_event_id)
				webhook_id,
				platform_event_id,
				event_type,
				status,
				attempt_count,
				attempted_at
			FROM webhook_deliveries
			WHERE tenant_id = $1
			  AND ($2 = '' OR webhook_id = $2)
			  AND ($3 = '' OR event_type = $3)
			ORDER BY webhook_id, platform_event_id, attempted_at DESC, id DESC
		)
		SELECT webhook_id, platform_event_id, event_type, attempt_count
		FROM latest
		WHERE status = 'dead_letter'
		  AND ($4::timestamptz IS NULL OR attempted_at >= $4)
		  AND ($5::timestamptz IS NULL OR attempted_at <= $5)
		ORDER BY attempt_count DESC, webhook_id ASC, platform_event_id ASC
		LIMIT $6
	`, tenantID, webhookID, eventType, since, until, limit)
	if err != nil {
		return nil, fmt.Errorf("list dead-letter replay candidates: %w", err)
	}
	defer rows.Close()

	out := make([]webhookReplayCandidate, 0, limit)
	for rows.Next() {
		var item webhookReplayCandidate
		if err := rows.Scan(&item.webhookID, &item.platformEventID, &item.eventType, &item.attemptCount); err != nil {
			return nil, fmt.Errorf("scan dead-letter replay candidate: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate dead-letter replay candidates: %w", err)
	}
	return out, nil
}

func (s *Store) getPlatformEventForTenant(ctx context.Context, tenantID string, eventID string) (models.PlatformEvent, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, event_type, source_service, aggregate_type, aggregate_id, payload_json, created_at
		FROM platform_events
		WHERE tenant_id = $1
		  AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(eventID))

	var (
		item        models.PlatformEvent
		payloadJSON []byte
	)
	if err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.EventType,
		&item.SourceService,
		&item.AggregateType,
		&item.AggregateID,
		&payloadJSON,
		&item.CreatedAt,
	); err != nil {
		if isNoRows(err) {
			return models.PlatformEvent{}, false, nil
		}
		return models.PlatformEvent{}, false, fmt.Errorf("get platform event: %w", err)
	}

	item.Payload = map[string]any{}
	if len(payloadJSON) > 0 {
		if err := json.Unmarshal(payloadJSON, &item.Payload); err != nil {
			return models.PlatformEvent{}, false, fmt.Errorf("decode platform event payload: %w", err)
		}
	}
	return item, true, nil
}

func webhookRetryDelay(attemptCount int, baseDelaySeconds int, maxDelaySeconds int) time.Duration {
	if baseDelaySeconds < minWebhookRetryDelaySeconds {
		baseDelaySeconds = minWebhookRetryDelaySeconds
	}
	if maxDelaySeconds < baseDelaySeconds {
		maxDelaySeconds = baseDelaySeconds
	}

	baseDelay := time.Duration(baseDelaySeconds) * time.Second
	maxDelay := time.Duration(maxDelaySeconds) * time.Second
	if attemptCount <= 1 {
		return baseDelay
	}

	delay := baseDelay
	for i := 1; i < attemptCount; i++ {
		delay *= 2
		if delay >= maxDelay {
			return maxDelay
		}
	}
	return delay
}

func computeWebhookSuccessRate(delivered int64, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(delivered) / float64(total)
}

func (s *Store) listWebhookIntegrationRecordsForDispatch(ctx context.Context, tenantID string, webhookID string) ([]webhookIntegrationRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	webhookID = strings.TrimSpace(webhookID)

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, endpoint_url, event_types_json, headers_json, status,
		       retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds,
		       secret_encrypted, last_attempt_at, last_success_at, created_by, updated_by, created_at, updated_at
		FROM webhook_integrations
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND ($2 = '' OR id = $2)
		ORDER BY updated_at DESC, id DESC
	`, tenantID, webhookID)
	if err != nil {
		return nil, fmt.Errorf("list webhook integrations for dispatch: %w", err)
	}
	defer rows.Close()

	out := make([]webhookIntegrationRecord, 0)
	for rows.Next() {
		record, err := scanWebhookIntegrationRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan webhook integration dispatch row: %w", err)
		}
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhook integration dispatch rows: %w", err)
	}
	return out, nil
}

func (s *Store) getWebhookIntegrationRecordForTenant(ctx context.Context, tenantID string, webhookID string) (webhookIntegrationRecord, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	webhookID = strings.TrimSpace(webhookID)

	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, endpoint_url, event_types_json, headers_json, status,
		       retry_max_attempts, retry_base_delay_seconds, retry_max_delay_seconds,
		       secret_encrypted, last_attempt_at, last_success_at, created_by, updated_by, created_at, updated_at
		FROM webhook_integrations
		WHERE tenant_id = $1
		  AND id = $2
	`, tenantID, webhookID)
	record, err := scanWebhookIntegrationRecord(row)
	if err != nil {
		if isNoRows(err) {
			return webhookIntegrationRecord{}, false, nil
		}
		return webhookIntegrationRecord{}, false, fmt.Errorf("get webhook integration: %w", err)
	}
	return record, true, nil
}

func (s *Store) sendWebhookDelivery(ctx context.Context, client *http.Client, webhook webhookIntegrationRecord, event models.PlatformEvent, deliveryID string) (bool, int, string, string) {
	payload := map[string]any{
		"delivery_id": deliveryID,
		"webhook_id":  webhook.integration.ID,
		"event":       event,
		"sent_at":     time.Now().UTC(),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return false, 0, "", fmt.Sprintf("marshal webhook payload: %v", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook.integration.EndpointURL, bytes.NewReader(encoded))
	if err != nil {
		return false, 0, "", fmt.Sprintf("create webhook request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "USS-Webhooks/1.0")
	request.Header.Set("X-USS-Webhook-ID", webhook.integration.ID)
	request.Header.Set("X-USS-Event-Type", event.EventType)
	request.Header.Set("X-USS-Delivery-ID", deliveryID)
	for key, value := range webhook.integration.Headers {
		request.Header.Set(key, value)
	}

	if strings.TrimSpace(webhook.secretEncrypted) != "" {
		secret, err := s.decryptIngestionWebhookSecret(webhook.integration.TenantID, webhook.integration.ID, "webhook_integration", webhook.secretEncrypted)
		if err != nil {
			return false, 0, "", fmt.Sprintf("decrypt webhook secret: %v", err)
		}
		signature := computeIngestionWebhookHMAC(secret, encoded, sha256.New)
		request.Header.Set("X-USS-Signature", "sha256="+signature)
	}

	response, err := client.Do(request)
	if err != nil {
		return false, 0, "", fmt.Sprintf("perform webhook request: %v", err)
	}
	defer response.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	bodyText := strings.TrimSpace(string(bodyBytes))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return true, response.StatusCode, bodyText, ""
	}
	return false, response.StatusCode, bodyText, fmt.Sprintf("unexpected status code %d", response.StatusCode)
}

func (s *Store) insertWebhookDelivery(ctx context.Context, item models.WebhookDelivery) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO webhook_deliveries (
			id, tenant_id, webhook_id, platform_event_id, event_type, status, attempt_count,
			response_status, response_body, error_message, attempted_at, next_attempt_at, delivered_at, dead_lettered_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13, $14, $15
		)
	`, item.ID, item.TenantID, item.WebhookID, item.PlatformEventID, item.EventType, item.Status, item.AttemptCount, item.ResponseStatus,
		item.ResponseBody, item.ErrorMessage, item.AttemptedAt, item.NextAttemptAt, item.DeliveredAt, item.DeadLetteredAt, item.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert webhook delivery: %w", err)
	}
	return nil
}

func (s *Store) updateWebhookDeliveryStatusSummary(ctx context.Context, tenantID string, webhookID string, attemptedAt time.Time, deliveredAt *time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE webhook_integrations
		SET last_attempt_at = $3,
		    last_success_at = CASE
		        WHEN $4 IS NOT NULL THEN $4
		        ELSE last_success_at
		    END,
		    updated_at = $3
		WHERE tenant_id = $1
		  AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(webhookID), attemptedAt, deliveredAt)
	if err != nil {
		return fmt.Errorf("update webhook integration delivery summary: %w", err)
	}
	return nil
}

func scanWebhookIntegrationRecord(row interface{ Scan(dest ...any) error }) (webhookIntegrationRecord, error) {
	var (
		record         webhookIntegrationRecord
		eventTypesJSON []byte
		headersJSON    []byte
	)

	err := row.Scan(
		&record.integration.ID,
		&record.integration.TenantID,
		&record.integration.Name,
		&record.integration.EndpointURL,
		&eventTypesJSON,
		&headersJSON,
		&record.integration.Status,
		&record.integration.RetryMaxAttempts,
		&record.integration.RetryBaseDelaySeconds,
		&record.integration.RetryMaxDelaySeconds,
		&record.secretEncrypted,
		&record.integration.LastAttemptAt,
		&record.integration.LastSuccessAt,
		&record.integration.CreatedBy,
		&record.integration.UpdatedBy,
		&record.integration.CreatedAt,
		&record.integration.UpdatedAt,
	)
	if err != nil {
		return webhookIntegrationRecord{}, err
	}

	if len(eventTypesJSON) > 0 {
		if err := json.Unmarshal(eventTypesJSON, &record.integration.EventTypes); err != nil {
			return webhookIntegrationRecord{}, fmt.Errorf("decode webhook event types: %w", err)
		}
	}
	if len(headersJSON) > 0 {
		if err := json.Unmarshal(headersJSON, &record.integration.Headers); err != nil {
			return webhookIntegrationRecord{}, fmt.Errorf("decode webhook headers: %w", err)
		}
	}

	record.integration.EventTypes = normalizeWebhookEventTypes(record.integration.EventTypes)
	record.integration.Headers = sanitizeWebhookHeaders(record.integration.Headers)
	record.integration.Status = normalizeWebhookIntegrationStatus(record.integration.Status)
	record.integration.RetryMaxAttempts, record.integration.RetryBaseDelaySeconds, record.integration.RetryMaxDelaySeconds, err = normalizeWebhookRetryPolicy(
		record.integration.RetryMaxAttempts,
		record.integration.RetryBaseDelaySeconds,
		record.integration.RetryMaxDelaySeconds,
	)
	if err != nil {
		return webhookIntegrationRecord{}, err
	}
	record.integration.SecretSet = strings.TrimSpace(record.secretEncrypted) != ""
	return record, nil
}

func scanWebhookDelivery(row interface{ Scan(dest ...any) error }) (models.WebhookDelivery, error) {
	var item models.WebhookDelivery
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.WebhookID,
		&item.PlatformEventID,
		&item.EventType,
		&item.Status,
		&item.AttemptCount,
		&item.ResponseStatus,
		&item.ResponseBody,
		&item.ErrorMessage,
		&item.AttemptedAt,
		&item.NextAttemptAt,
		&item.DeliveredAt,
		&item.DeadLetteredAt,
		&item.CreatedAt,
	)
	if err != nil {
		return models.WebhookDelivery{}, err
	}
	item.Status = normalizeWebhookDeliveryStatus(item.Status)
	return item, nil
}

func validateWebhookEndpointURL(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("endpoint_url must be a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("endpoint_url must use http or https")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("endpoint_url must include a host")
	}
	return nil
}

func normalizeWebhookIntegrationStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active", "paused", "disabled":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeWebhookDeliveryStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "delivered", "failed", "scheduled_retry", "dead_letter":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeWebhookRetryPolicy(maxAttempts int, baseDelaySeconds int, maxDelaySeconds int) (int, int, int, error) {
	if maxAttempts <= 0 {
		maxAttempts = defaultWebhookRetryMaxAttempts
	}
	if maxAttempts < minWebhookRetryMaxAttempts || maxAttempts > maxWebhookRetryMaxAttempts {
		return 0, 0, 0, fmt.Errorf("retry_max_attempts must be between %d and %d", minWebhookRetryMaxAttempts, maxWebhookRetryMaxAttempts)
	}

	if baseDelaySeconds <= 0 {
		baseDelaySeconds = defaultWebhookRetryBaseDelaySeconds
	}
	if baseDelaySeconds < minWebhookRetryDelaySeconds || baseDelaySeconds > maxWebhookRetryDelaySeconds {
		return 0, 0, 0, fmt.Errorf("retry_base_delay_seconds must be between %d and %d", minWebhookRetryDelaySeconds, maxWebhookRetryDelaySeconds)
	}

	if maxDelaySeconds <= 0 {
		maxDelaySeconds = defaultWebhookRetryMaxDelaySeconds
	}
	if maxDelaySeconds < minWebhookRetryDelaySeconds || maxDelaySeconds > maxWebhookRetryDelaySeconds {
		return 0, 0, 0, fmt.Errorf("retry_max_delay_seconds must be between %d and %d", minWebhookRetryDelaySeconds, maxWebhookRetryDelaySeconds)
	}
	if maxDelaySeconds < baseDelaySeconds {
		return 0, 0, 0, fmt.Errorf("retry_max_delay_seconds must be greater than or equal to retry_base_delay_seconds")
	}

	return maxAttempts, baseDelaySeconds, maxDelaySeconds, nil
}

func normalizeWebhookEventTypes(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
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

func sanitizeWebhookHeaders(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		trimmedKey := strings.TrimSpace(key)
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" || trimmedValue == "" {
			continue
		}
		lowerKey := strings.ToLower(trimmedKey)
		if lowerKey == "content-length" || lowerKey == "host" {
			continue
		}
		out[trimmedKey] = trimmedValue
	}
	return out
}

func webhookAcceptsEvent(eventTypes []string, eventType string) bool {
	if len(eventTypes) == 0 {
		return true
	}
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	for _, value := range eventTypes {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "*" || normalized == eventType {
			return true
		}
	}
	return false
}

func truncateWebhookText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func nextWebhookIntegrationID() string {
	value := atomic.AddUint64(&webhookIntegrationSequence, 1)
	return fmt.Sprintf("webhook-integration-%d-%06d", time.Now().UTC().Unix(), value)
}

func nextWebhookDeliveryID() string {
	value := atomic.AddUint64(&webhookDeliverySequence, 1)
	return fmt.Sprintf("webhook-delivery-%d-%06d", time.Now().UTC().Unix(), value)
}
