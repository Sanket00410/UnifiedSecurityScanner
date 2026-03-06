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
	return command.RowsAffected() > 0, nil
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
		job           *models.ScanJob
		createJobErr  error
		policyDenied  *PolicyDeniedError
		internalError string
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
			internalError = err.Error()
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

	if createJobErr != nil {
		return models.IngestionWebhookResponse{}, fmt.Errorf("create scan job from ingestion event: %s", internalError)
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
		labels[strings.TrimSpace(key)] = value
	}

	metadata := map[string]any{}
	for key, value := range request.Metadata {
		metadata[strings.TrimSpace(key)] = value
	}

	return models.IngestionWebhookRequest{
		EventType:   eventType,
		ExternalID:  strings.TrimSpace(request.ExternalID),
		TargetKind:  targetKind,
		Target:      target,
		Profile:     profile,
		Tools:       tools,
		RequestedBy: requestedBy,
		Labels:      labels,
		Metadata:    metadata,
	}
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
