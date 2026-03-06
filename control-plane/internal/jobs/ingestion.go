package jobs

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/models"
)

type ingestionSourceRecord struct {
	Source     models.IngestionSource
	SecretHash string
}

func (s *Store) ListIngestionSourcesForTenant(ctx context.Context, tenantID string, limit int) ([]models.IngestionSource, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, provider, enabled, target_kind, target, profile, tools,
		       labels_json, created_by, updated_by, last_event_at, created_at, updated_at, secret_hash
		FROM ingestion_sources
		WHERE tenant_id = $1
		ORDER BY updated_at DESC, name ASC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list ingestion sources: %w", err)
	}
	defer rows.Close()

	items := make([]models.IngestionSource, 0, limit)
	for rows.Next() {
		record, err := scanIngestionSourceRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ingestion source row: %w", err)
		}
		items = append(items, record.Source)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ingestion sources: %w", err)
	}

	return items, nil
}

func (s *Store) GetIngestionSourceForTenant(ctx context.Context, tenantID string, sourceID string) (models.IngestionSource, bool, error) {
	record, found, err := s.getIngestionSourceRecordForTenant(ctx, tenantID, sourceID)
	if err != nil {
		return models.IngestionSource{}, false, err
	}
	if !found {
		return models.IngestionSource{}, false, nil
	}
	return record.Source, true, nil
}

func (s *Store) CreateIngestionSourceForTenant(ctx context.Context, tenantID string, actor string, request models.CreateIngestionSourceRequest) (models.CreatedIngestionSource, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	now := time.Now().UTC()

	if err := s.enforceIngestionSourceLimit(ctx, tenantID); err != nil {
		return models.CreatedIngestionSource{}, err
	}

	source := normalizeCreateIngestionSourceRequest(tenantID, actor, request, now)
	token, err := nextIngestionToken()
	if err != nil {
		return models.CreatedIngestionSource{}, fmt.Errorf("create ingestion token: %w", err)
	}
	secretHash := auth.TokenHash(token)
	labelsJSON, err := json.Marshal(source.Labels)
	if err != nil {
		return models.CreatedIngestionSource{}, fmt.Errorf("marshal ingestion source labels: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO ingestion_sources (
			id, tenant_id, name, provider, enabled, target_kind, target, profile, tools,
			labels_json, secret_hash, created_by, updated_by, last_event_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9,
			$10, $11, $12, $13, NULL, $14, $14
		)
	`, source.ID, source.TenantID, source.Name, source.Provider, source.Enabled, source.TargetKind, source.Target, source.Profile, source.Tools,
		labelsJSON, secretHash, source.CreatedBy, source.UpdatedBy, now)
	if err != nil {
		return models.CreatedIngestionSource{}, fmt.Errorf("insert ingestion source: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      source.TenantID,
		EventType:     "ingestion_source.created",
		SourceService: "control-plane",
		AggregateType: "ingestion_source",
		AggregateID:   source.ID,
		Payload: map[string]any{
			"name":        source.Name,
			"provider":    source.Provider,
			"enabled":     source.Enabled,
			"target_kind": source.TargetKind,
			"profile":     source.Profile,
		},
		CreatedAt: now,
	})

	return models.CreatedIngestionSource{
		Source:      source,
		IngestToken: token,
	}, nil
}

func (s *Store) UpdateIngestionSourceForTenant(ctx context.Context, tenantID string, sourceID string, actor string, request models.UpdateIngestionSourceRequest) (models.IngestionSource, bool, error) {
	existing, found, err := s.GetIngestionSourceForTenant(ctx, tenantID, sourceID)
	if err != nil {
		return models.IngestionSource{}, false, err
	}
	if !found {
		return models.IngestionSource{}, false, nil
	}

	now := time.Now().UTC()
	updated := normalizeUpdateIngestionSourceRequest(existing, strings.TrimSpace(actor), request, now)
	labelsJSON, err := json.Marshal(updated.Labels)
	if err != nil {
		return models.IngestionSource{}, false, fmt.Errorf("marshal ingestion source labels: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE ingestion_sources
		SET name = $3,
		    provider = $4,
		    enabled = $5,
		    target_kind = $6,
		    target = $7,
		    profile = $8,
		    tools = $9,
		    labels_json = $10,
		    updated_by = $11,
		    updated_at = $12
		WHERE tenant_id = $1 AND id = $2
		RETURNING id, tenant_id, name, provider, enabled, target_kind, target, profile, tools,
		          labels_json, created_by, updated_by, last_event_at, created_at, updated_at, secret_hash
	`, strings.TrimSpace(tenantID), strings.TrimSpace(sourceID), updated.Name, updated.Provider, updated.Enabled,
		updated.TargetKind, updated.Target, updated.Profile, updated.Tools, labelsJSON, updated.UpdatedBy, now)

	record, err := scanIngestionSourceRecord(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.IngestionSource{}, false, nil
		}
		return models.IngestionSource{}, false, fmt.Errorf("update ingestion source: %w", err)
	}

	return record.Source, true, nil
}

func (s *Store) DeleteIngestionSourceForTenant(ctx context.Context, tenantID string, sourceID string) (bool, error) {
	command, err := s.pool.Exec(ctx, `
		DELETE FROM ingestion_sources
		WHERE tenant_id = $1 AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(sourceID))
	if err != nil {
		return false, fmt.Errorf("delete ingestion source: %w", err)
	}
	deleted := command.RowsAffected() > 0
	if deleted {
		_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
			TenantID:      strings.TrimSpace(tenantID),
			EventType:     "ingestion_source.deleted",
			SourceService: "control-plane",
			AggregateType: "ingestion_source",
			AggregateID:   strings.TrimSpace(sourceID),
			Payload:       map[string]any{},
			CreatedAt:     time.Now().UTC(),
		})
	}
	return deleted, nil
}

func (s *Store) RotateIngestionSourceTokenForTenant(ctx context.Context, tenantID string, sourceID string, actor string) (models.RotateIngestionSourceTokenResponse, bool, error) {
	existing, found, err := s.GetIngestionSourceForTenant(ctx, tenantID, sourceID)
	if err != nil {
		return models.RotateIngestionSourceTokenResponse{}, false, err
	}
	if !found {
		return models.RotateIngestionSourceTokenResponse{}, false, nil
	}

	token, err := nextIngestionToken()
	if err != nil {
		return models.RotateIngestionSourceTokenResponse{}, true, fmt.Errorf("create ingestion token: %w", err)
	}
	secretHash := auth.TokenHash(token)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = existing.UpdatedBy
	}
	if actor == "" {
		actor = existing.CreatedBy
	}
	now := time.Now().UTC()

	row := s.pool.QueryRow(ctx, `
		UPDATE ingestion_sources
		SET secret_hash = $3,
		    updated_by = $4,
		    updated_at = $5
		WHERE tenant_id = $1 AND id = $2
		RETURNING id, tenant_id, name, provider, enabled, target_kind, target, profile, tools,
		          labels_json, created_by, updated_by, last_event_at, created_at, updated_at, secret_hash
	`, strings.TrimSpace(tenantID), strings.TrimSpace(sourceID), secretHash, actor, now)

	record, err := scanIngestionSourceRecord(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.RotateIngestionSourceTokenResponse{}, false, nil
		}
		return models.RotateIngestionSourceTokenResponse{}, true, fmt.Errorf("rotate ingestion source token: %w", err)
	}

	return models.RotateIngestionSourceTokenResponse{
		Source:      record.Source,
		IngestToken: token,
	}, true, nil
}

func (s *Store) ListIngestionEventsForTenant(ctx context.Context, tenantID string, sourceID string, limit int) ([]models.IngestionEvent, error) {
	tenantID = strings.TrimSpace(tenantID)
	sourceID = strings.TrimSpace(sourceID)
	if tenantID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	var (
		rows pgx.Rows
		err  error
	)

	if sourceID == "" {
		rows, err = s.pool.Query(ctx, `
			SELECT id, tenant_id, source_id, event_type, external_id, payload_json, status,
			       error_message, created_scan_job_id, policy_id, policy_rule_hits_json, created_at, updated_at
			FROM ingestion_events
			WHERE tenant_id = $1
			ORDER BY created_at DESC, id DESC
			LIMIT $2
		`, tenantID, limit)
	} else {
		rows, err = s.pool.Query(ctx, `
			SELECT id, tenant_id, source_id, event_type, external_id, payload_json, status,
			       error_message, created_scan_job_id, policy_id, policy_rule_hits_json, created_at, updated_at
			FROM ingestion_events
			WHERE tenant_id = $1 AND source_id = $2
			ORDER BY created_at DESC, id DESC
			LIMIT $3
		`, tenantID, sourceID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list ingestion events: %w", err)
	}
	defer rows.Close()

	items := make([]models.IngestionEvent, 0, limit)
	for rows.Next() {
		item, err := scanIngestionEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ingestion event row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ingestion events: %w", err)
	}

	return items, nil
}

func (s *Store) HandleIngestionWebhook(ctx context.Context, sourceID string, rawToken string, request models.IngestionWebhookRequest) (models.IngestionWebhookResponse, error) {
	record, found, err := s.getIngestionSourceRecordByID(ctx, sourceID)
	if err != nil {
		return models.IngestionWebhookResponse{}, err
	}
	if !found {
		return models.IngestionWebhookResponse{}, ErrIngestionSourceNotFound
	}

	if subtle.ConstantTimeCompare([]byte(auth.TokenHash(rawToken)), []byte(record.SecretHash)) != 1 {
		return models.IngestionWebhookResponse{}, ErrInvalidIngestionToken
	}
	if !record.Source.Enabled {
		return models.IngestionWebhookResponse{}, ErrIngestionSourceDisabled
	}

	normalized := normalizeIngestionWebhookRequest(record.Source, request)
	if normalized.TargetKind == "" || normalized.Target == "" {
		return models.IngestionWebhookResponse{}, fmt.Errorf("ingestion webhook requires target_kind and target")
	}

	if normalized.ExternalID != "" {
		existing, found, err := s.getIngestionEventByExternalID(ctx, record.Source.TenantID, record.Source.ID, normalized.ExternalID)
		if err != nil {
			return models.IngestionWebhookResponse{}, err
		}
		if found {
			response := models.IngestionWebhookResponse{
				Event:     existing,
				Duplicate: true,
			}
			if strings.TrimSpace(existing.CreatedScanJobID) != "" {
				job, jobFound, err := s.GetForTenant(ctx, record.Source.TenantID, existing.CreatedScanJobID)
				if err == nil && jobFound {
					response.Job = &job
				}
			}
			return response, nil
		}
	}

	now := time.Now().UTC()
	event := models.IngestionEvent{
		ID:         nextIngestionEventID(),
		TenantID:   record.Source.TenantID,
		SourceID:   record.Source.ID,
		EventType:  normalized.EventType,
		ExternalID: normalized.ExternalID,
		Status:     "accepted",
		Payload: map[string]any{
			"event_type":   normalized.EventType,
			"external_id":  normalized.ExternalID,
			"target_kind":  normalized.TargetKind,
			"target":       normalized.Target,
			"profile":      normalized.Profile,
			"tools":        normalized.Tools,
			"requested_by": normalized.RequestedBy,
			"labels":       normalized.Labels,
			"metadata":     normalized.Metadata,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	var (
		job          *models.ScanJob
		createJobErr error
		policyDenied *PolicyDeniedError
	)

	createdJob, err := s.CreateForTenant(ctx, record.Source.TenantID, models.CreateScanJobRequest{
		TenantID:    record.Source.TenantID,
		TargetKind:  normalized.TargetKind,
		Target:      normalized.Target,
		Profile:     normalized.Profile,
		RequestedBy: normalized.RequestedBy,
		Tools:       normalized.Tools,
	})
	if err != nil {
		if errors.As(err, &policyDenied) {
			event.Status = "policy_denied"
			event.ErrorMessage = policyDenied.Error()
			event.PolicyID = strings.TrimSpace(policyDenied.PolicyID)
			event.PolicyRuleHits = append([]string(nil), policyDenied.RuleHits...)
		} else {
			event.Status = "failed"
			event.ErrorMessage = "scan job creation failed"
			createJobErr = err
		}
	} else {
		job = &createdJob
		event.Status = "queued"
		event.CreatedScanJobID = createdJob.ID
	}

	insertedEvent, err := s.insertIngestionEvent(ctx, event)
	if err != nil {
		var pgErr *pgconn.PgError
		if normalized.ExternalID != "" && errors.As(err, &pgErr) && pgErr.Code == "23505" {
			existing, found, lookupErr := s.getIngestionEventByExternalID(ctx, record.Source.TenantID, record.Source.ID, normalized.ExternalID)
			if lookupErr != nil {
				return models.IngestionWebhookResponse{}, lookupErr
			}
			if found {
				response := models.IngestionWebhookResponse{
					Event:     existing,
					Duplicate: true,
				}
				if strings.TrimSpace(existing.CreatedScanJobID) != "" {
					job, jobFound, lookupErr := s.GetForTenant(ctx, record.Source.TenantID, existing.CreatedScanJobID)
					if lookupErr == nil && jobFound {
						response.Job = &job
					}
				}
				return response, nil
			}
		}
		return models.IngestionWebhookResponse{}, err
	}
	event = insertedEvent

	if _, updateErr := s.pool.Exec(ctx, `
		UPDATE ingestion_sources
		SET last_event_at = $3,
		    updated_at = $3,
		    updated_by = $4
		WHERE tenant_id = $1 AND id = $2
	`, record.Source.TenantID, record.Source.ID, now, normalized.RequestedBy); updateErr != nil {
		return models.IngestionWebhookResponse{}, fmt.Errorf("update ingestion source last_event_at: %w", updateErr)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      record.Source.TenantID,
		EventType:     "ingestion_event.processed",
		SourceService: "control-plane",
		AggregateType: "ingestion_source",
		AggregateID:   record.Source.ID,
		Payload: map[string]any{
			"event_id":            event.ID,
			"external_id":         event.ExternalID,
			"status":              event.Status,
			"created_scan_job_id": event.CreatedScanJobID,
		},
		CreatedAt: now,
	})

	if createJobErr != nil {
		return models.IngestionWebhookResponse{}, createJobErr
	}

	return models.IngestionWebhookResponse{
		Event:     event,
		Job:       job,
		Duplicate: false,
	}, nil
}

func (s *Store) getIngestionSourceRecordForTenant(ctx context.Context, tenantID string, sourceID string) (ingestionSourceRecord, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, provider, enabled, target_kind, target, profile, tools,
		       labels_json, created_by, updated_by, last_event_at, created_at, updated_at, secret_hash
		FROM ingestion_sources
		WHERE tenant_id = $1 AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(sourceID))

	record, err := scanIngestionSourceRecord(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ingestionSourceRecord{}, false, nil
		}
		return ingestionSourceRecord{}, false, fmt.Errorf("select ingestion source: %w", err)
	}
	return record, true, nil
}

func (s *Store) getIngestionSourceRecordByID(ctx context.Context, sourceID string) (ingestionSourceRecord, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, provider, enabled, target_kind, target, profile, tools,
		       labels_json, created_by, updated_by, last_event_at, created_at, updated_at, secret_hash
		FROM ingestion_sources
		WHERE id = $1
	`, strings.TrimSpace(sourceID))

	record, err := scanIngestionSourceRecord(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ingestionSourceRecord{}, false, nil
		}
		return ingestionSourceRecord{}, false, fmt.Errorf("select ingestion source by id: %w", err)
	}
	return record, true, nil
}

func (s *Store) getIngestionEventByExternalID(ctx context.Context, tenantID string, sourceID string, externalID string) (models.IngestionEvent, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, source_id, event_type, external_id, payload_json, status,
		       error_message, created_scan_job_id, policy_id, policy_rule_hits_json, created_at, updated_at
		FROM ingestion_events
		WHERE tenant_id = $1 AND source_id = $2 AND external_id = $3
	`, strings.TrimSpace(tenantID), strings.TrimSpace(sourceID), strings.TrimSpace(externalID))

	event, err := scanIngestionEvent(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.IngestionEvent{}, false, nil
		}
		return models.IngestionEvent{}, false, fmt.Errorf("select ingestion event by external id: %w", err)
	}
	return event, true, nil
}

func (s *Store) insertIngestionEvent(ctx context.Context, event models.IngestionEvent) (models.IngestionEvent, error) {
	payloadJSON, err := json.Marshal(event.Payload)
	if err != nil {
		return models.IngestionEvent{}, fmt.Errorf("marshal ingestion payload: %w", err)
	}
	ruleHitsJSON, err := json.Marshal(event.PolicyRuleHits)
	if err != nil {
		return models.IngestionEvent{}, fmt.Errorf("marshal ingestion policy rule hits: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO ingestion_events (
			id, tenant_id, source_id, event_type, external_id, payload_json, status,
			error_message, created_scan_job_id, policy_id, policy_rule_hits_json, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $12
		)
		RETURNING id, tenant_id, source_id, event_type, external_id, payload_json, status,
		          error_message, created_scan_job_id, policy_id, policy_rule_hits_json, created_at, updated_at
	`, event.ID, event.TenantID, event.SourceID, event.EventType, event.ExternalID, payloadJSON, event.Status,
		event.ErrorMessage, event.CreatedScanJobID, event.PolicyID, ruleHitsJSON, event.CreatedAt)
	inserted, err := scanIngestionEvent(row)
	if err != nil {
		return models.IngestionEvent{}, fmt.Errorf("insert ingestion event: %w", err)
	}

	return inserted, nil
}

func normalizeCreateIngestionSourceRequest(tenantID string, actor string, request models.CreateIngestionSourceRequest, now time.Time) models.IngestionSource {
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = "Unnamed Ingestion Source"
	}

	provider := normalizeIngestionProvider(request.Provider)
	targetKind := strings.ToLower(strings.TrimSpace(request.TargetKind))
	target := strings.TrimSpace(request.Target)
	profile := strings.TrimSpace(request.Profile)
	if profile == "" {
		profile = "balanced"
	}

	tools := sanitizeTools(request.Tools)
	if len(tools) == 0 {
		tools = defaultToolsForTargetKind(targetKind)
	}

	labels := request.Labels
	if labels == nil {
		labels = map[string]any{}
	}

	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}

	return models.IngestionSource{
		ID:          nextIngestionSourceID(),
		TenantID:    tenantID,
		Name:        name,
		Provider:    provider,
		Enabled:     enabled,
		TargetKind:  targetKind,
		Target:      target,
		Profile:     profile,
		Tools:       tools,
		Labels:      labels,
		CreatedBy:   actor,
		UpdatedBy:   actor,
		LastEventAt: nil,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func normalizeUpdateIngestionSourceRequest(existing models.IngestionSource, actor string, request models.UpdateIngestionSourceRequest, now time.Time) models.IngestionSource {
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = existing.Name
	}

	provider := normalizeIngestionProvider(request.Provider)
	if provider == "" {
		provider = existing.Provider
	}

	targetKind := strings.ToLower(strings.TrimSpace(request.TargetKind))
	if targetKind == "" {
		targetKind = existing.TargetKind
	}

	target := strings.TrimSpace(request.Target)
	if target == "" {
		target = existing.Target
	}

	profile := strings.TrimSpace(request.Profile)
	if profile == "" {
		profile = existing.Profile
	}
	if profile == "" {
		profile = "balanced"
	}

	tools := sanitizeTools(request.Tools)
	if len(tools) == 0 {
		tools = existing.Tools
	}
	if len(tools) == 0 {
		tools = defaultToolsForTargetKind(targetKind)
	}

	enabled := existing.Enabled
	if request.Enabled != nil {
		enabled = *request.Enabled
	}

	labels := request.Labels
	if labels == nil {
		labels = existing.Labels
	}
	if labels == nil {
		labels = map[string]any{}
	}

	if actor == "" {
		actor = existing.UpdatedBy
	}
	if actor == "" {
		actor = existing.CreatedBy
	}

	existing.Name = name
	existing.Provider = provider
	existing.Enabled = enabled
	existing.TargetKind = targetKind
	existing.Target = target
	existing.Profile = profile
	existing.Tools = tools
	existing.Labels = labels
	existing.UpdatedBy = actor
	existing.UpdatedAt = now
	return existing
}

func normalizeIngestionWebhookRequest(source models.IngestionSource, request models.IngestionWebhookRequest) models.IngestionWebhookRequest {
	request = normalizeProviderWebhookRequest(source, request)

	eventType := strings.TrimSpace(request.EventType)
	if eventType == "" {
		eventType = source.Provider + ".event"
		if strings.TrimSpace(source.Provider) == "" {
			eventType = "generic.event"
		}
	}

	targetKind := strings.ToLower(strings.TrimSpace(request.TargetKind))
	if targetKind == "" {
		targetKind = source.TargetKind
	}

	target := strings.TrimSpace(request.Target)
	if target == "" {
		target = source.Target
	}

	profile := strings.TrimSpace(request.Profile)
	if profile == "" {
		profile = source.Profile
	}
	if profile == "" {
		profile = "balanced"
	}

	tools := sanitizeTools(request.Tools)
	if len(tools) == 0 {
		tools = source.Tools
	}
	if len(tools) == 0 {
		tools = defaultToolsForTargetKind(targetKind)
	}

	requestedBy := strings.TrimSpace(request.RequestedBy)
	if requestedBy == "" {
		requestedBy = "ingestion:" + source.Provider
	}
	if requestedBy == "ingestion:" {
		requestedBy = "ingestion:generic"
	}

	labels := map[string]any{}
	for key, value := range source.Labels {
		labels[key] = value
	}
	for key, value := range request.Labels {
		normalized := strings.TrimSpace(key)
		if normalized == "" {
			continue
		}
		labels[normalized] = value
	}

	metadata := map[string]any{}
	for key, value := range request.Metadata {
		normalized := strings.TrimSpace(key)
		if normalized == "" {
			continue
		}
		metadata[normalized] = value
	}
	if len(request.Headers) > 0 {
		metadata["webhook_headers"] = request.Headers
	}
	if len(request.Payload) > 0 {
		metadata["provider_payload"] = request.Payload
	}

	return models.IngestionWebhookRequest{
		EventType:   eventType,
		ExternalID:  strings.TrimSpace(request.ExternalID),
		TargetKind:  targetKind,
		Target:      target,
		Profile:     profile,
		Tools:       tools,
		RequestedBy: requestedBy,
		Headers:     request.Headers,
		Payload:     request.Payload,
		Labels:      labels,
		Metadata:    metadata,
	}
}

func normalizeProviderWebhookRequest(source models.IngestionSource, request models.IngestionWebhookRequest) models.IngestionWebhookRequest {
	switch normalizeIngestionProvider(source.Provider) {
	case "github":
		return normalizeGitHubWebhookRequest(source, request)
	case "gitlab":
		return normalizeGitLabWebhookRequest(source, request)
	case "jenkins":
		return normalizeJenkinsWebhookRequest(source, request)
	default:
		return request
	}
}

func normalizeGitHubWebhookRequest(source models.IngestionSource, request models.IngestionWebhookRequest) models.IngestionWebhookRequest {
	headers := normalizeHeaderMap(request.Headers)
	eventName := strings.TrimSpace(firstNonEmptyIngestionString(
		request.EventType,
		headers["x-github-event"],
		headers["x-event-key"],
	))
	if eventName != "" && !strings.Contains(eventName, ".") {
		eventName = "github." + strings.ToLower(eventName)
	}
	if strings.TrimSpace(request.EventType) == "" && eventName != "" {
		request.EventType = eventName
	}

	if strings.TrimSpace(request.ExternalID) == "" {
		request.ExternalID = firstNonEmptyIngestionString(
			headers["x-github-delivery"],
			lookupMapString(request.Payload, "delivery"),
			lookupNestedString(request.Payload, "check_run", "id"),
			lookupNestedString(request.Payload, "workflow_run", "id"),
		)
	}

	repoFullName := firstNonEmptyIngestionString(
		lookupNestedString(request.Payload, "repository", "full_name"),
		lookupNestedString(request.Payload, "repository", "name"),
	)
	repoTarget := firstNonEmptyIngestionString(
		lookupNestedString(request.Payload, "repository", "clone_url"),
		lookupNestedString(request.Payload, "repository", "html_url"),
	)
	branch := normalizeBranchName(firstNonEmptyIngestionString(
		lookupMapString(request.Payload, "ref"),
		lookupNestedString(request.Payload, "pull_request", "head", "ref"),
	))
	commit := firstNonEmptyIngestionString(
		lookupMapString(request.Payload, "after"),
		lookupNestedString(request.Payload, "head_commit", "id"),
		lookupNestedString(request.Payload, "pull_request", "head", "sha"),
	)

	if strings.TrimSpace(request.TargetKind) == "" && strings.TrimSpace(source.TargetKind) == "" && repoTarget != "" {
		request.TargetKind = "repo"
	}
	if strings.TrimSpace(request.Target) == "" && strings.TrimSpace(source.Target) == "" && repoTarget != "" {
		request.Target = repoTarget
	}
	if request.Labels == nil {
		request.Labels = map[string]any{}
	}
	if request.Metadata == nil {
		request.Metadata = map[string]any{}
	}
	if repoFullName != "" {
		request.Labels["repo"] = repoFullName
	}
	if branch != "" {
		request.Labels["branch"] = branch
	}
	if commit != "" {
		request.Labels["commit"] = commit
	}
	if action := strings.TrimSpace(lookupMapString(request.Payload, "action")); action != "" {
		request.Labels["action"] = action
	}
	if prNumber := firstNonEmptyIngestionString(
		lookupNestedString(request.Payload, "pull_request", "number"),
		lookupNestedString(request.Payload, "issue", "number"),
	); prNumber != "" {
		request.Labels["pr_number"] = prNumber
	}
	request.Metadata["provider"] = "github"
	if sourceRef := strings.TrimSpace(lookupNestedString(request.Payload, "sender", "login")); sourceRef != "" {
		request.Metadata["sender"] = sourceRef
	}
	return request
}

func normalizeGitLabWebhookRequest(source models.IngestionSource, request models.IngestionWebhookRequest) models.IngestionWebhookRequest {
	headers := normalizeHeaderMap(request.Headers)

	eventName := strings.TrimSpace(firstNonEmptyIngestionString(
		request.EventType,
		headers["x-gitlab-event"],
		lookupMapString(request.Payload, "object_kind"),
	))
	if eventName != "" && !strings.Contains(eventName, ".") {
		eventName = "gitlab." + strings.ToLower(strings.ReplaceAll(eventName, " ", "_"))
	}
	if strings.TrimSpace(request.EventType) == "" && eventName != "" {
		request.EventType = eventName
	}

	if strings.TrimSpace(request.ExternalID) == "" {
		request.ExternalID = firstNonEmptyIngestionString(
			headers["x-gitlab-event-uuid"],
			headers["x-gitlab-delivery"],
			lookupNestedString(request.Payload, "object_attributes", "id"),
			lookupNestedString(request.Payload, "commit", "id"),
		)
	}

	repoFullName := firstNonEmptyIngestionString(
		lookupNestedString(request.Payload, "project", "path_with_namespace"),
		lookupNestedString(request.Payload, "project", "name"),
	)
	repoTarget := firstNonEmptyIngestionString(
		lookupNestedString(request.Payload, "project", "http_url"),
		lookupNestedString(request.Payload, "project", "http_url_to_repo"),
		lookupNestedString(request.Payload, "project", "web_url"),
	)
	branch := normalizeBranchName(firstNonEmptyIngestionString(
		lookupMapString(request.Payload, "ref"),
		lookupNestedString(request.Payload, "object_attributes", "source_branch"),
	))
	commit := firstNonEmptyIngestionString(
		lookupMapString(request.Payload, "checkout_sha"),
		lookupNestedString(request.Payload, "object_attributes", "last_commit", "id"),
	)

	if strings.TrimSpace(request.TargetKind) == "" && strings.TrimSpace(source.TargetKind) == "" && repoTarget != "" {
		request.TargetKind = "repo"
	}
	if strings.TrimSpace(request.Target) == "" && strings.TrimSpace(source.Target) == "" && repoTarget != "" {
		request.Target = repoTarget
	}
	if request.Labels == nil {
		request.Labels = map[string]any{}
	}
	if request.Metadata == nil {
		request.Metadata = map[string]any{}
	}
	if repoFullName != "" {
		request.Labels["repo"] = repoFullName
	}
	if branch != "" {
		request.Labels["branch"] = branch
	}
	if commit != "" {
		request.Labels["commit"] = commit
	}
	if action := strings.TrimSpace(lookupNestedString(request.Payload, "object_attributes", "action")); action != "" {
		request.Labels["action"] = action
	}
	request.Metadata["provider"] = "gitlab"
	if user := strings.TrimSpace(lookupMapString(request.Payload, "user_username")); user != "" {
		request.Metadata["sender"] = user
	}
	return request
}

func normalizeJenkinsWebhookRequest(source models.IngestionSource, request models.IngestionWebhookRequest) models.IngestionWebhookRequest {
	headers := normalizeHeaderMap(request.Headers)
	if strings.TrimSpace(request.EventType) == "" {
		request.EventType = firstNonEmptyIngestionString(
			headers["x-jenkins-event"],
			"jenkins.build",
		)
		if !strings.Contains(request.EventType, ".") {
			request.EventType = "jenkins." + strings.ToLower(strings.TrimSpace(request.EventType))
		}
	}
	if strings.TrimSpace(request.ExternalID) == "" {
		request.ExternalID = firstNonEmptyIngestionString(
			lookupMapString(request.Payload, "build_id"),
			lookupMapString(request.Payload, "build_number"),
			headers["x-jenkins-build-number"],
		)
	}

	repoTarget := firstNonEmptyIngestionString(
		lookupMapString(request.Payload, "scm_url"),
		lookupNestedString(request.Payload, "scm", "url"),
	)
	if strings.TrimSpace(request.TargetKind) == "" && strings.TrimSpace(source.TargetKind) == "" && repoTarget != "" {
		request.TargetKind = "repo"
	}
	if strings.TrimSpace(request.Target) == "" && strings.TrimSpace(source.Target) == "" && repoTarget != "" {
		request.Target = repoTarget
	}

	if request.Labels == nil {
		request.Labels = map[string]any{}
	}
	if request.Metadata == nil {
		request.Metadata = map[string]any{}
	}
	if jobName := firstNonEmptyIngestionString(lookupMapString(request.Payload, "job_name"), headers["x-jenkins-job"]); jobName != "" {
		request.Labels["job"] = jobName
	}
	if branch := normalizeBranchName(lookupMapString(request.Payload, "branch")); branch != "" {
		request.Labels["branch"] = branch
	}
	if buildURL := lookupMapString(request.Payload, "build_url"); strings.TrimSpace(buildURL) != "" {
		request.Metadata["build_url"] = strings.TrimSpace(buildURL)
	}
	request.Metadata["provider"] = "jenkins"
	return request
}

func normalizeHeaderMap(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		normalizedValue := strings.TrimSpace(value)
		if normalizedKey == "" || normalizedValue == "" {
			continue
		}
		out[normalizedKey] = normalizedValue
	}
	return out
}

func lookupMapString(values map[string]any, key string) string {
	if len(values) == 0 {
		return ""
	}
	return anyToString(values[key])
}

func lookupNestedString(values map[string]any, path ...string) string {
	if len(values) == 0 || len(path) == 0 {
		return ""
	}
	var current any = values
	for _, part := range path {
		node, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = node[part]
		if !ok {
			return ""
		}
	}
	return anyToString(current)
}

func anyToString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return fmt.Sprintf("%d", int64(typed))
		}
		return strings.TrimSpace(fmt.Sprintf("%f", typed))
	case int:
		return fmt.Sprintf("%d", typed)
	case int64:
		return fmt.Sprintf("%d", typed)
	case int32:
		return fmt.Sprintf("%d", typed)
	case uint64:
		return fmt.Sprintf("%d", typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

func firstNonEmptyIngestionString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func normalizeBranchName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimPrefix(trimmed, prefix)
		}
	}
	return trimmed
}

func normalizeIngestionProvider(provider string) string {
	normalized := strings.ToLower(strings.TrimSpace(provider))
	if normalized == "" {
		return "generic"
	}
	return normalized
}

func scanIngestionSourceRecord(row interface{ Scan(dest ...any) error }) (ingestionSourceRecord, error) {
	var (
		record      ingestionSourceRecord
		labelsJSON  []byte
		lastEventAt *time.Time
	)

	err := row.Scan(
		&record.Source.ID,
		&record.Source.TenantID,
		&record.Source.Name,
		&record.Source.Provider,
		&record.Source.Enabled,
		&record.Source.TargetKind,
		&record.Source.Target,
		&record.Source.Profile,
		&record.Source.Tools,
		&labelsJSON,
		&record.Source.CreatedBy,
		&record.Source.UpdatedBy,
		&lastEventAt,
		&record.Source.CreatedAt,
		&record.Source.UpdatedAt,
		&record.SecretHash,
	)
	if err != nil {
		return ingestionSourceRecord{}, err
	}

	record.Source.LastEventAt = lastEventAt
	if len(labelsJSON) > 0 {
		if err := json.Unmarshal(labelsJSON, &record.Source.Labels); err != nil {
			return ingestionSourceRecord{}, fmt.Errorf("decode ingestion source labels: %w", err)
		}
	}
	if record.Source.Labels == nil {
		record.Source.Labels = map[string]any{}
	}

	return record, nil
}

func scanIngestionEvent(row interface{ Scan(dest ...any) error }) (models.IngestionEvent, error) {
	var (
		event        models.IngestionEvent
		payloadJSON  []byte
		ruleHitsJSON []byte
	)

	err := row.Scan(
		&event.ID,
		&event.TenantID,
		&event.SourceID,
		&event.EventType,
		&event.ExternalID,
		&payloadJSON,
		&event.Status,
		&event.ErrorMessage,
		&event.CreatedScanJobID,
		&event.PolicyID,
		&ruleHitsJSON,
		&event.CreatedAt,
		&event.UpdatedAt,
	)
	if err != nil {
		return models.IngestionEvent{}, err
	}

	if len(payloadJSON) > 0 {
		if err := json.Unmarshal(payloadJSON, &event.Payload); err != nil {
			return models.IngestionEvent{}, fmt.Errorf("decode ingestion payload: %w", err)
		}
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}

	if len(ruleHitsJSON) > 0 {
		if err := json.Unmarshal(ruleHitsJSON, &event.PolicyRuleHits); err != nil {
			return models.IngestionEvent{}, fmt.Errorf("decode ingestion policy rule hits: %w", err)
		}
	}
	if event.PolicyRuleHits == nil {
		event.PolicyRuleHits = []string{}
	}

	return event, nil
}

func nextIngestionSourceID() string {
	sequence := atomic.AddUint64(&ingestionSourceSequence, 1)
	return fmt.Sprintf("ingestion-source-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextIngestionEventID() string {
	sequence := atomic.AddUint64(&ingestionEventSequence, 1)
	return fmt.Sprintf("ingestion-event-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextIngestionToken() (string, error) {
	buffer := make([]byte, 20)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	return "uss_ingest_" + hex.EncodeToString(buffer), nil
}
