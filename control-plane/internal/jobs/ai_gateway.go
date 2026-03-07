package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) GetAIGatewayPolicyForTenant(ctx context.Context, tenantID string) (models.AIGatewayPolicy, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, default_model, allowed_models, max_input_chars, max_output_chars,
		       require_grounding, require_evidence_refs, redact_secrets, updated_by, updated_at
		FROM ai_gateway_policies
		WHERE tenant_id = $1
	`, tenantID)
	item, err := scanAIGatewayPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return defaultAIGatewayPolicy(tenantID), false, nil
		}
		return models.AIGatewayPolicy{}, false, fmt.Errorf("get ai gateway policy: %w", err)
	}
	return item, true, nil
}

func (s *Store) UpsertAIGatewayPolicyForTenant(ctx context.Context, tenantID string, actor string, request models.UpsertAIGatewayPolicyRequest) (models.AIGatewayPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	current, _, err := s.GetAIGatewayPolicyForTenant(ctx, tenantID)
	if err != nil {
		return models.AIGatewayPolicy{}, err
	}

	if value := strings.TrimSpace(request.DefaultModel); value != "" {
		current.DefaultModel = value
	}
	if request.AllowedModels != nil {
		current.AllowedModels = sanitizeAIGatewayModels(request.AllowedModels)
	}
	if request.MaxInputChars != nil {
		current.MaxInputChars = *request.MaxInputChars
	}
	if request.MaxOutputChars != nil {
		current.MaxOutputChars = *request.MaxOutputChars
	}
	if request.RequireGrounding != nil {
		current.RequireGrounding = *request.RequireGrounding
	}
	if request.RequireEvidenceRefs != nil {
		current.RequireEvidenceRefs = *request.RequireEvidenceRefs
	}
	if request.RedactSecrets != nil {
		current.RedactSecrets = *request.RedactSecrets
	}
	if current.MaxInputChars <= 0 || current.MaxOutputChars <= 0 {
		return models.AIGatewayPolicy{}, fmt.Errorf("max_input_chars and max_output_chars must be greater than zero")
	}
	if len(current.AllowedModels) == 0 {
		current.AllowedModels = []string{"gpt-4o-mini"}
	}
	if strings.TrimSpace(current.DefaultModel) == "" {
		current.DefaultModel = current.AllowedModels[0]
	}
	if !containsNormalized(current.AllowedModels, current.DefaultModel) {
		return models.AIGatewayPolicy{}, ErrAIPolicyModelDenied
	}

	current.TenantID = tenantID
	current.UpdatedBy = actor
	current.UpdatedAt = time.Now().UTC()

	row := s.pool.QueryRow(ctx, `
		INSERT INTO ai_gateway_policies (
			tenant_id, default_model, allowed_models, max_input_chars, max_output_chars,
			require_grounding, require_evidence_refs, redact_secrets, updated_by, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10
		)
		ON CONFLICT (tenant_id) DO UPDATE SET
			default_model = EXCLUDED.default_model,
			allowed_models = EXCLUDED.allowed_models,
			max_input_chars = EXCLUDED.max_input_chars,
			max_output_chars = EXCLUDED.max_output_chars,
			require_grounding = EXCLUDED.require_grounding,
			require_evidence_refs = EXCLUDED.require_evidence_refs,
			redact_secrets = EXCLUDED.redact_secrets,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
		RETURNING tenant_id, default_model, allowed_models, max_input_chars, max_output_chars,
		          require_grounding, require_evidence_refs, redact_secrets, updated_by, updated_at
	`, current.TenantID, current.DefaultModel, current.AllowedModels, current.MaxInputChars, current.MaxOutputChars,
		current.RequireGrounding, current.RequireEvidenceRefs, current.RedactSecrets, current.UpdatedBy, current.UpdatedAt)

	updated, err := scanAIGatewayPolicy(row)
	if err != nil {
		return models.AIGatewayPolicy{}, fmt.Errorf("upsert ai gateway policy: %w", err)
	}
	return updated, nil
}

func (s *Store) ListAITriageRequestsForTenant(ctx context.Context, tenantID string, requestKind string, limit int) ([]models.AITriageRequest, error) {
	tenantID = strings.TrimSpace(tenantID)
	requestKind = strings.ToLower(strings.TrimSpace(requestKind))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, request_kind, model, input_text, evidence_refs_json, finding_ids_json,
		       response_text, safety_state, created_by, created_at
		FROM ai_triage_requests
		WHERE tenant_id = $1
		  AND ($2 = '' OR request_kind = $2)
		ORDER BY created_at DESC, id DESC
		LIMIT $3
	`, tenantID, requestKind, limit)
	if err != nil {
		return nil, fmt.Errorf("list ai triage requests: %w", err)
	}
	defer rows.Close()

	items := make([]models.AITriageRequest, 0, limit)
	for rows.Next() {
		item, err := scanAITriageRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ai triage request row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ai triage request rows: %w", err)
	}
	return items, nil
}

func (s *Store) CreateAITriageSummaryForTenant(ctx context.Context, tenantID string, actor string, request models.CreateAITriageSummaryRequest) (models.AITriageRequest, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	policy, _, err := s.GetAIGatewayPolicyForTenant(ctx, tenantID)
	if err != nil {
		return models.AITriageRequest{}, err
	}
	model := strings.TrimSpace(request.Model)
	if model == "" {
		model = policy.DefaultModel
	}
	if !containsNormalized(policy.AllowedModels, model) {
		return models.AITriageRequest{}, ErrAIPolicyModelDenied
	}

	inputText := strings.TrimSpace(request.InputText)
	if int64(len(inputText)) > policy.MaxInputChars {
		return models.AITriageRequest{}, ErrAIPolicyInputTooLarge
	}
	evidenceRefs := sanitizeDesignStringList(request.EvidenceRefs)
	if policy.RequireEvidenceRefs && len(evidenceRefs) == 0 {
		return models.AITriageRequest{}, ErrAIPolicyEvidenceRequired
	}
	findingIDs := sanitizeDesignStringList(request.FindingIDs)

	if policy.RedactSecrets {
		inputText = redactAIGatewaySecrets(inputText)
	}

	maxOutputChars := policy.MaxOutputChars
	if request.MaxOutputChars != nil && *request.MaxOutputChars > 0 && *request.MaxOutputChars < maxOutputChars {
		maxOutputChars = *request.MaxOutputChars
	}
	responseText := buildAIEvidenceGroundedSummary(inputText, evidenceRefs, findingIDs, maxOutputChars, policy.RequireGrounding)
	safetyState := "grounded"
	if !policy.RequireGrounding {
		safetyState = "unguarded"
	}

	now := time.Now().UTC()
	item := models.AITriageRequest{
		ID:           nextAITriageRequestID(),
		TenantID:     tenantID,
		RequestKind:  "finding_summary",
		Model:        model,
		InputText:    inputText,
		EvidenceRefs: evidenceRefs,
		FindingIDs:   findingIDs,
		ResponseText: responseText,
		SafetyState:  safetyState,
		CreatedBy:    actor,
		CreatedAt:    now,
	}

	evidenceJSON, err := json.Marshal(item.EvidenceRefs)
	if err != nil {
		return models.AITriageRequest{}, fmt.Errorf("marshal ai triage evidence refs: %w", err)
	}
	findingsJSON, err := json.Marshal(item.FindingIDs)
	if err != nil {
		return models.AITriageRequest{}, fmt.Errorf("marshal ai triage finding ids: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO ai_triage_requests (
			id, tenant_id, request_kind, model, input_text, evidence_refs_json, finding_ids_json,
			response_text, safety_state, created_by, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11
		)
		RETURNING id, tenant_id, request_kind, model, input_text, evidence_refs_json, finding_ids_json,
		          response_text, safety_state, created_by, created_at
	`, item.ID, item.TenantID, item.RequestKind, item.Model, item.InputText, evidenceJSON, findingsJSON,
		item.ResponseText, item.SafetyState, item.CreatedBy, item.CreatedAt)

	created, err := scanAITriageRequest(row)
	if err != nil {
		return models.AITriageRequest{}, fmt.Errorf("create ai triage summary: %w", err)
	}
	return created, nil
}

func defaultAIGatewayPolicy(tenantID string) models.AIGatewayPolicy {
	return models.AIGatewayPolicy{
		TenantID:            strings.TrimSpace(tenantID),
		DefaultModel:        "gpt-4o-mini",
		AllowedModels:       []string{"gpt-4o-mini"},
		MaxInputChars:       12000,
		MaxOutputChars:      3000,
		RequireGrounding:    true,
		RequireEvidenceRefs: true,
		RedactSecrets:       true,
		UpdatedBy:           "system",
		UpdatedAt:           time.Now().UTC(),
	}
}

func scanAIGatewayPolicy(row interface{ Scan(dest ...any) error }) (models.AIGatewayPolicy, error) {
	var item models.AIGatewayPolicy
	err := row.Scan(
		&item.TenantID,
		&item.DefaultModel,
		&item.AllowedModels,
		&item.MaxInputChars,
		&item.MaxOutputChars,
		&item.RequireGrounding,
		&item.RequireEvidenceRefs,
		&item.RedactSecrets,
		&item.UpdatedBy,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.AIGatewayPolicy{}, err
	}
	item.AllowedModels = sanitizeAIGatewayModels(item.AllowedModels)
	return item, nil
}

func scanAITriageRequest(row interface{ Scan(dest ...any) error }) (models.AITriageRequest, error) {
	var (
		item         models.AITriageRequest
		evidenceJSON []byte
		findingsJSON []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.RequestKind,
		&item.Model,
		&item.InputText,
		&evidenceJSON,
		&findingsJSON,
		&item.ResponseText,
		&item.SafetyState,
		&item.CreatedBy,
		&item.CreatedAt,
	)
	if err != nil {
		return models.AITriageRequest{}, err
	}
	if len(evidenceJSON) > 0 {
		if err := json.Unmarshal(evidenceJSON, &item.EvidenceRefs); err != nil {
			return models.AITriageRequest{}, fmt.Errorf("decode ai triage evidence refs: %w", err)
		}
	}
	if len(findingsJSON) > 0 {
		if err := json.Unmarshal(findingsJSON, &item.FindingIDs); err != nil {
			return models.AITriageRequest{}, fmt.Errorf("decode ai triage finding ids: %w", err)
		}
	}
	item.EvidenceRefs = sanitizeDesignStringList(item.EvidenceRefs)
	item.FindingIDs = sanitizeDesignStringList(item.FindingIDs)
	return item, nil
}

func sanitizeAIGatewayModels(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		normalized := strings.ToLower(trimmed)
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func containsNormalized(values []string, candidate string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == candidate {
			return true
		}
	}
	return false
}

func redactAIGatewaySecrets(input string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|api_key|token)\s*=\s*[^&\s]+`),
		regexp.MustCompile(`(?i)(authorization)\s*:\s*bearer\s+[^\s]+`),
	}
	redacted := strings.TrimSpace(input)
	for _, pattern := range patterns {
		redacted = pattern.ReplaceAllStringFunc(redacted, func(match string) string {
			parts := strings.SplitN(match, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[0]) + "=[REDACTED]"
			}
			if strings.Contains(strings.ToLower(match), "authorization") {
				return "authorization: bearer [REDACTED]"
			}
			return "[REDACTED]"
		})
	}
	return redacted
}

func buildAIEvidenceGroundedSummary(inputText string, evidenceRefs []string, findingIDs []string, maxChars int64, requireGrounding bool) string {
	parts := []string{}
	if requireGrounding {
		parts = append(parts, "Evidence-grounded summary only.")
	}
	if len(findingIDs) > 0 {
		parts = append(parts, "Findings: "+strings.Join(findingIDs, ", "))
	}
	if len(evidenceRefs) > 0 {
		parts = append(parts, "Evidence: "+strings.Join(evidenceRefs, ", "))
	}
	if inputText != "" {
		parts = append(parts, "Input: "+inputText)
	}
	if len(parts) == 0 {
		parts = append(parts, "No input supplied.")
	}
	summary := strings.Join(parts, "\n")
	if maxChars > 0 && int64(len(summary)) > maxChars {
		return summary[:maxChars]
	}
	return summary
}

func nextAITriageRequestID() string {
	value := atomic.AddUint64(&aiTriageRequestSequence, 1)
	return fmt.Sprintf("ai-triage-%d-%06d", time.Now().UTC().Unix(), value)
}
