package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) ListWebTargetsForTenant(ctx context.Context, tenantID string, targetType string, limit int) ([]models.WebTarget, error) {
	tenantID = strings.TrimSpace(tenantID)
	targetType = normalizeWebTargetType(targetType)
	if tenantID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, target_type, base_url, api_schema_url,
		       in_scope_patterns, out_of_scope_patterns, labels_json,
		       created_by, updated_by, created_at, updated_at
		FROM web_targets
		WHERE tenant_id = $1
		  AND ($2 = '' OR target_type = $2)
		ORDER BY updated_at DESC, name ASC
		LIMIT $3
	`, tenantID, targetType, limit)
	if err != nil {
		return nil, fmt.Errorf("list web targets: %w", err)
	}
	defer rows.Close()

	items := make([]models.WebTarget, 0, limit)
	for rows.Next() {
		item, err := scanWebTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("scan web target row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate web targets: %w", err)
	}
	return items, nil
}

func (s *Store) GetWebTargetForTenant(ctx context.Context, tenantID string, targetID string) (models.WebTarget, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, target_type, base_url, api_schema_url,
		       in_scope_patterns, out_of_scope_patterns, labels_json,
		       created_by, updated_by, created_at, updated_at
		FROM web_targets
		WHERE tenant_id = $1 AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID))

	item, err := scanWebTarget(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.WebTarget{}, false, nil
		}
		return models.WebTarget{}, false, fmt.Errorf("select web target: %w", err)
	}
	return item, true, nil
}

func (s *Store) CreateWebTargetForTenant(ctx context.Context, tenantID string, actor string, request models.CreateWebTargetRequest) (models.WebTarget, error) {
	now := time.Now().UTC()
	item := normalizeCreateWebTargetRequest(strings.TrimSpace(tenantID), strings.TrimSpace(actor), request, now)
	if item.BaseURL == "" {
		return models.WebTarget{}, fmt.Errorf("base_url is required")
	}

	labelsJSON, err := json.Marshal(item.Labels)
	if err != nil {
		return models.WebTarget{}, fmt.Errorf("marshal web target labels: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO web_targets (
			id, tenant_id, name, target_type, base_url, api_schema_url,
			in_scope_patterns, out_of_scope_patterns, labels_json,
			created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9,
			$10, $11, $12, $12
		)
	`, item.ID, item.TenantID, item.Name, item.TargetType, item.BaseURL, item.APISchemaURL,
		item.InScopePatterns, item.OutOfScopePatterns, labelsJSON,
		item.CreatedBy, item.UpdatedBy, item.CreatedAt)
	if err != nil {
		return models.WebTarget{}, fmt.Errorf("insert web target: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      item.TenantID,
		EventType:     "web_target.created",
		SourceService: "control-plane",
		AggregateType: "web_target",
		AggregateID:   item.ID,
		Payload: map[string]any{
			"name":        item.Name,
			"target_type": item.TargetType,
			"base_url":    item.BaseURL,
		},
		CreatedAt: now,
	})

	return item, nil
}

func (s *Store) UpdateWebTargetForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.UpdateWebTargetRequest) (models.WebTarget, bool, error) {
	existing, found, err := s.GetWebTargetForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebTarget{}, false, err
	}
	if !found {
		return models.WebTarget{}, false, nil
	}

	now := time.Now().UTC()
	item := normalizeUpdateWebTargetRequest(existing, strings.TrimSpace(actor), request, now)
	if item.BaseURL == "" {
		return models.WebTarget{}, true, fmt.Errorf("base_url is required")
	}

	labelsJSON, err := json.Marshal(item.Labels)
	if err != nil {
		return models.WebTarget{}, true, fmt.Errorf("marshal web target labels: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE web_targets
		SET name = $3,
		    target_type = $4,
		    base_url = $5,
		    api_schema_url = $6,
		    in_scope_patterns = $7,
		    out_of_scope_patterns = $8,
		    labels_json = $9,
		    updated_by = $10,
		    updated_at = $11
		WHERE tenant_id = $1 AND id = $2
		RETURNING id, tenant_id, name, target_type, base_url, api_schema_url,
		          in_scope_patterns, out_of_scope_patterns, labels_json,
		          created_by, updated_by, created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID), item.Name, item.TargetType, item.BaseURL, item.APISchemaURL,
		item.InScopePatterns, item.OutOfScopePatterns, labelsJSON, item.UpdatedBy, now)

	updated, err := scanWebTarget(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.WebTarget{}, false, nil
		}
		return models.WebTarget{}, true, fmt.Errorf("update web target: %w", err)
	}

	return updated, true, nil
}

func (s *Store) DeleteWebTargetForTenant(ctx context.Context, tenantID string, targetID string) (bool, error) {
	command, err := s.pool.Exec(ctx, `
		DELETE FROM web_targets
		WHERE tenant_id = $1 AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID))
	if err != nil {
		return false, fmt.Errorf("delete web target: %w", err)
	}
	deleted := command.RowsAffected() > 0
	if deleted {
		_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
			TenantID:      strings.TrimSpace(tenantID),
			EventType:     "web_target.deleted",
			SourceService: "control-plane",
			AggregateType: "web_target",
			AggregateID:   strings.TrimSpace(targetID),
			Payload:       map[string]any{},
			CreatedAt:     time.Now().UTC(),
		})
	}
	return deleted, nil
}

func (s *Store) ListWebAuthProfilesForTenant(ctx context.Context, tenantID string, limit int) ([]models.WebAuthProfile, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, auth_type, login_url, username_secret_ref, password_secret_ref,
		       bearer_token_secret_ref, csrf_mode, session_bootstrap_json, test_personas_json, token_refresh_strategy,
		       enabled, created_by, updated_by, created_at, updated_at
		FROM web_auth_profiles
		WHERE tenant_id = $1
		ORDER BY updated_at DESC, name ASC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list web auth profiles: %w", err)
	}
	defer rows.Close()

	items := make([]models.WebAuthProfile, 0, limit)
	for rows.Next() {
		item, err := scanWebAuthProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan web auth profile row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate web auth profiles: %w", err)
	}
	return items, nil
}

func (s *Store) GetWebAuthProfileForTenant(ctx context.Context, tenantID string, profileID string) (models.WebAuthProfile, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, auth_type, login_url, username_secret_ref, password_secret_ref,
		       bearer_token_secret_ref, csrf_mode, session_bootstrap_json, test_personas_json, token_refresh_strategy,
		       enabled, created_by, updated_by, created_at, updated_at
		FROM web_auth_profiles
		WHERE tenant_id = $1 AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))

	item, err := scanWebAuthProfile(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.WebAuthProfile{}, false, nil
		}
		return models.WebAuthProfile{}, false, fmt.Errorf("select web auth profile: %w", err)
	}
	return item, true, nil
}

func (s *Store) CreateWebAuthProfileForTenant(ctx context.Context, tenantID string, actor string, request models.CreateWebAuthProfileRequest) (models.WebAuthProfile, error) {
	now := time.Now().UTC()
	item := normalizeCreateWebAuthProfileRequest(strings.TrimSpace(tenantID), strings.TrimSpace(actor), request, now)
	if item.Name == "" {
		return models.WebAuthProfile{}, fmt.Errorf("name is required")
	}

	sessionBootstrapJSON, err := json.Marshal(item.SessionBootstrap)
	if err != nil {
		return models.WebAuthProfile{}, fmt.Errorf("marshal auth profile session bootstrap: %w", err)
	}
	testPersonasJSON, err := json.Marshal(item.TestPersonas)
	if err != nil {
		return models.WebAuthProfile{}, fmt.Errorf("marshal auth profile personas: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO web_auth_profiles (
			id, tenant_id, name, auth_type, login_url, username_secret_ref, password_secret_ref,
			bearer_token_secret_ref, csrf_mode, session_bootstrap_json, test_personas_json, token_refresh_strategy,
			enabled, created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12,
			$13, $14, $15, $16, $16
		)
	`, item.ID, item.TenantID, item.Name, item.AuthType, item.LoginURL, item.UsernameSecretRef, item.PasswordSecretRef,
		item.BearerTokenSecretRef, item.CSRFMode, sessionBootstrapJSON, testPersonasJSON, item.TokenRefreshStrategy,
		item.Enabled, item.CreatedBy, item.UpdatedBy, item.CreatedAt)
	if err != nil {
		return models.WebAuthProfile{}, fmt.Errorf("insert web auth profile: %w", err)
	}

	return item, nil
}

func (s *Store) UpdateWebAuthProfileForTenant(ctx context.Context, tenantID string, profileID string, actor string, request models.UpdateWebAuthProfileRequest) (models.WebAuthProfile, bool, error) {
	existing, found, err := s.GetWebAuthProfileForTenant(ctx, tenantID, profileID)
	if err != nil {
		return models.WebAuthProfile{}, false, err
	}
	if !found {
		return models.WebAuthProfile{}, false, nil
	}

	now := time.Now().UTC()
	item := normalizeUpdateWebAuthProfileRequest(existing, strings.TrimSpace(actor), request, now)
	if item.Name == "" {
		return models.WebAuthProfile{}, true, fmt.Errorf("name is required")
	}

	sessionBootstrapJSON, err := json.Marshal(item.SessionBootstrap)
	if err != nil {
		return models.WebAuthProfile{}, true, fmt.Errorf("marshal auth profile session bootstrap: %w", err)
	}
	testPersonasJSON, err := json.Marshal(item.TestPersonas)
	if err != nil {
		return models.WebAuthProfile{}, true, fmt.Errorf("marshal auth profile personas: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE web_auth_profiles
		SET name = $3,
		    auth_type = $4,
		    login_url = $5,
		    username_secret_ref = $6,
		    password_secret_ref = $7,
		    bearer_token_secret_ref = $8,
		    csrf_mode = $9,
		    session_bootstrap_json = $10,
		    test_personas_json = $11,
		    token_refresh_strategy = $12,
		    enabled = $13,
		    updated_by = $14,
		    updated_at = $15
		WHERE tenant_id = $1 AND id = $2
		RETURNING id, tenant_id, name, auth_type, login_url, username_secret_ref, password_secret_ref,
		          bearer_token_secret_ref, csrf_mode, session_bootstrap_json, test_personas_json, token_refresh_strategy,
		          enabled, created_by, updated_by, created_at, updated_at
	`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID), item.Name, item.AuthType, item.LoginURL, item.UsernameSecretRef,
		item.PasswordSecretRef, item.BearerTokenSecretRef, item.CSRFMode, sessionBootstrapJSON, testPersonasJSON,
		item.TokenRefreshStrategy, item.Enabled, item.UpdatedBy, now)

	updated, err := scanWebAuthProfile(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.WebAuthProfile{}, false, nil
		}
		return models.WebAuthProfile{}, true, fmt.Errorf("update web auth profile: %w", err)
	}

	return updated, true, nil
}

func (s *Store) DeleteWebAuthProfileForTenant(ctx context.Context, tenantID string, profileID string) (bool, error) {
	command, err := s.pool.Exec(ctx, `
		DELETE FROM web_auth_profiles
		WHERE tenant_id = $1 AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))
	if err != nil {
		return false, fmt.Errorf("delete web auth profile: %w", err)
	}
	return command.RowsAffected() > 0, nil
}

func (s *Store) GetWebCrawlPolicyForTenant(ctx context.Context, tenantID string, targetID string) (models.WebCrawlPolicy, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, web_target_id, auth_profile_id, safe_mode, max_depth,
		       max_requests, request_budget_per_minute, allow_paths, deny_paths, seed_urls,
		       headers_json, created_by, updated_by, created_at, updated_at
		FROM web_crawl_policies
		WHERE tenant_id = $1 AND web_target_id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID))

	item, err := scanWebCrawlPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.WebCrawlPolicy{}, false, nil
		}
		return models.WebCrawlPolicy{}, false, fmt.Errorf("select web crawl policy: %w", err)
	}
	return item, true, nil
}

func (s *Store) UpsertWebCrawlPolicyForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.UpsertWebCrawlPolicyRequest) (models.WebCrawlPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	targetID = strings.TrimSpace(targetID)
	actor = strings.TrimSpace(actor)

	_, targetFound, err := s.GetWebTargetForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebCrawlPolicy{}, err
	}
	if !targetFound {
		return models.WebCrawlPolicy{}, ErrWebTargetNotFound
	}

	authProfileID := strings.TrimSpace(request.AuthProfileID)
	if authProfileID != "" {
		_, authProfileFound, err := s.GetWebAuthProfileForTenant(ctx, tenantID, authProfileID)
		if err != nil {
			return models.WebCrawlPolicy{}, err
		}
		if !authProfileFound {
			return models.WebCrawlPolicy{}, ErrWebAuthProfileNotFound
		}
	}

	existing, found, err := s.GetWebCrawlPolicyForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebCrawlPolicy{}, err
	}

	now := time.Now().UTC()
	item := models.WebCrawlPolicy{
		ID:                     nextWebCrawlPolicyID(),
		TenantID:               tenantID,
		WebTargetID:            targetID,
		AuthProfileID:          authProfileID,
		SafeMode:               true,
		MaxDepth:               3,
		MaxRequests:            500,
		RequestBudgetPerMinute: 120,
		AllowPaths:             []string{},
		DenyPaths:              []string{},
		SeedURLs:               []string{},
		Headers:                map[string]any{},
		CreatedBy:              actor,
		UpdatedBy:              actor,
		CreatedAt:              now,
		UpdatedAt:              now,
	}

	if found {
		item = existing
		item.AuthProfileID = authProfileID
		item.UpdatedBy = actor
		item.UpdatedAt = now
	}

	if request.SafeMode != nil {
		item.SafeMode = *request.SafeMode
	}
	if request.MaxDepth != nil {
		item.MaxDepth = *request.MaxDepth
	}
	if request.MaxRequests != nil {
		item.MaxRequests = *request.MaxRequests
	}
	if request.RequestBudgetPerMinute != nil {
		item.RequestBudgetPerMinute = *request.RequestBudgetPerMinute
	}
	if request.AllowPaths != nil {
		item.AllowPaths = sanitizeStringList(request.AllowPaths)
	}
	if request.DenyPaths != nil {
		item.DenyPaths = sanitizeStringList(request.DenyPaths)
	}
	if request.SeedURLs != nil {
		item.SeedURLs = sanitizeStringList(request.SeedURLs)
	}
	if request.Headers != nil {
		item.Headers = request.Headers
	}

	if item.MaxDepth < 0 || item.MaxRequests < 0 || item.RequestBudgetPerMinute < 0 {
		return models.WebCrawlPolicy{}, fmt.Errorf("crawl policy limits must be greater than or equal to zero")
	}
	if item.CreatedBy == "" {
		item.CreatedBy = "system"
	}
	if item.UpdatedBy == "" {
		item.UpdatedBy = item.CreatedBy
	}

	headersJSON, err := json.Marshal(item.Headers)
	if err != nil {
		return models.WebCrawlPolicy{}, fmt.Errorf("marshal crawl policy headers: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO web_crawl_policies (
			id, tenant_id, web_target_id, auth_profile_id, safe_mode, max_depth,
			max_requests, request_budget_per_minute, allow_paths, deny_paths, seed_urls,
			headers_json, created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14, $15, $15
		)
		ON CONFLICT (tenant_id, web_target_id) DO UPDATE SET
			auth_profile_id = EXCLUDED.auth_profile_id,
			safe_mode = EXCLUDED.safe_mode,
			max_depth = EXCLUDED.max_depth,
			max_requests = EXCLUDED.max_requests,
			request_budget_per_minute = EXCLUDED.request_budget_per_minute,
			allow_paths = EXCLUDED.allow_paths,
			deny_paths = EXCLUDED.deny_paths,
			seed_urls = EXCLUDED.seed_urls,
			headers_json = EXCLUDED.headers_json,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
		RETURNING id, tenant_id, web_target_id, auth_profile_id, safe_mode, max_depth,
		          max_requests, request_budget_per_minute, allow_paths, deny_paths, seed_urls,
		          headers_json, created_by, updated_by, created_at, updated_at
	`, item.ID, item.TenantID, item.WebTargetID, nullableString(item.AuthProfileID), item.SafeMode, item.MaxDepth,
		item.MaxRequests, item.RequestBudgetPerMinute, item.AllowPaths, item.DenyPaths, item.SeedURLs,
		headersJSON, item.CreatedBy, item.UpdatedBy, item.CreatedAt)
	updated, err := scanWebCrawlPolicy(row)
	if err != nil {
		return models.WebCrawlPolicy{}, fmt.Errorf("upsert web crawl policy: %w", err)
	}

	return updated, nil
}

func (s *Store) GetWebCoverageBaselineForTenant(ctx context.Context, tenantID string, targetID string) (models.WebCoverageBaseline, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, web_target_id, expected_route_count, expected_api_operation_count,
		       expected_auth_state_count, minimum_route_coverage, minimum_api_coverage, minimum_auth_coverage,
		       notes, created_by, updated_by, created_at, updated_at
		FROM web_coverage_baselines
		WHERE tenant_id = $1 AND web_target_id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID))

	item, err := scanWebCoverageBaseline(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.WebCoverageBaseline{}, false, nil
		}
		return models.WebCoverageBaseline{}, false, fmt.Errorf("select web coverage baseline: %w", err)
	}
	return item, true, nil
}

func (s *Store) UpsertWebCoverageBaselineForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.UpsertWebCoverageBaselineRequest) (models.WebCoverageBaseline, error) {
	tenantID = strings.TrimSpace(tenantID)
	targetID = strings.TrimSpace(targetID)
	actor = strings.TrimSpace(actor)

	_, targetFound, err := s.GetWebTargetForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebCoverageBaseline{}, err
	}
	if !targetFound {
		return models.WebCoverageBaseline{}, ErrWebTargetNotFound
	}

	existing, found, err := s.GetWebCoverageBaselineForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebCoverageBaseline{}, err
	}

	now := time.Now().UTC()
	item := models.WebCoverageBaseline{
		ID:                        nextWebCoverageBaselineID(),
		TenantID:                  tenantID,
		WebTargetID:               targetID,
		ExpectedRouteCount:        0,
		ExpectedAPIOperationCount: 0,
		ExpectedAuthStateCount:    0,
		MinimumRouteCoverage:      0,
		MinimumAPICoverage:        0,
		MinimumAuthCoverage:       0,
		Notes:                     "",
		CreatedBy:                 actor,
		UpdatedBy:                 actor,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	if found {
		item = existing
		item.UpdatedBy = actor
		item.UpdatedAt = now
	}

	if request.ExpectedRouteCount != nil {
		item.ExpectedRouteCount = *request.ExpectedRouteCount
	}
	if request.ExpectedAPIOperationCount != nil {
		item.ExpectedAPIOperationCount = *request.ExpectedAPIOperationCount
	}
	if request.ExpectedAuthStateCount != nil {
		item.ExpectedAuthStateCount = *request.ExpectedAuthStateCount
	}
	if request.MinimumRouteCoverage != nil {
		item.MinimumRouteCoverage = *request.MinimumRouteCoverage
	}
	if request.MinimumAPICoverage != nil {
		item.MinimumAPICoverage = *request.MinimumAPICoverage
	}
	if request.MinimumAuthCoverage != nil {
		item.MinimumAuthCoverage = *request.MinimumAuthCoverage
	}
	item.Notes = strings.TrimSpace(request.Notes)

	if item.ExpectedRouteCount < 0 || item.ExpectedAPIOperationCount < 0 || item.ExpectedAuthStateCount < 0 {
		return models.WebCoverageBaseline{}, fmt.Errorf("coverage baseline counts must be greater than or equal to zero")
	}
	if item.MinimumRouteCoverage < 0 || item.MinimumRouteCoverage > 100 ||
		item.MinimumAPICoverage < 0 || item.MinimumAPICoverage > 100 ||
		item.MinimumAuthCoverage < 0 || item.MinimumAuthCoverage > 100 {
		return models.WebCoverageBaseline{}, fmt.Errorf("coverage minimums must be between 0 and 100")
	}
	if item.CreatedBy == "" {
		item.CreatedBy = "system"
	}
	if item.UpdatedBy == "" {
		item.UpdatedBy = item.CreatedBy
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO web_coverage_baselines (
			id, tenant_id, web_target_id, expected_route_count, expected_api_operation_count,
			expected_auth_state_count, minimum_route_coverage, minimum_api_coverage, minimum_auth_coverage,
			notes, created_by, updated_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13, $13
		)
		ON CONFLICT (tenant_id, web_target_id) DO UPDATE SET
			expected_route_count = EXCLUDED.expected_route_count,
			expected_api_operation_count = EXCLUDED.expected_api_operation_count,
			expected_auth_state_count = EXCLUDED.expected_auth_state_count,
			minimum_route_coverage = EXCLUDED.minimum_route_coverage,
			minimum_api_coverage = EXCLUDED.minimum_api_coverage,
			minimum_auth_coverage = EXCLUDED.minimum_auth_coverage,
			notes = EXCLUDED.notes,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
		RETURNING id, tenant_id, web_target_id, expected_route_count, expected_api_operation_count,
		          expected_auth_state_count, minimum_route_coverage, minimum_api_coverage, minimum_auth_coverage,
		          notes, created_by, updated_by, created_at, updated_at
	`, item.ID, item.TenantID, item.WebTargetID, item.ExpectedRouteCount, item.ExpectedAPIOperationCount,
		item.ExpectedAuthStateCount, item.MinimumRouteCoverage, item.MinimumAPICoverage, item.MinimumAuthCoverage,
		item.Notes, item.CreatedBy, item.UpdatedBy, item.CreatedAt)

	updated, err := scanWebCoverageBaseline(row)
	if err != nil {
		return models.WebCoverageBaseline{}, fmt.Errorf("upsert web coverage baseline: %w", err)
	}
	return updated, nil
}

func (s *Store) ListWebRuntimeCoverageRunsForTenant(ctx context.Context, tenantID string, targetID string, limit int) ([]models.WebRuntimeCoverageRun, error) {
	tenantID = strings.TrimSpace(tenantID)
	targetID = strings.TrimSpace(targetID)
	if tenantID == "" || targetID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 2000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, web_target_id, scan_job_id, route_coverage, api_coverage, auth_coverage,
		       discovered_route_count, discovered_api_operation_count, discovered_auth_state_count,
		       evidence_ref, created_by, created_at
		FROM web_runtime_coverage_runs
		WHERE tenant_id = $1 AND web_target_id = $2
		ORDER BY created_at DESC
		LIMIT $3
	`, tenantID, targetID, limit)
	if err != nil {
		return nil, fmt.Errorf("list web runtime coverage runs: %w", err)
	}
	defer rows.Close()

	items := make([]models.WebRuntimeCoverageRun, 0, limit)
	for rows.Next() {
		item, err := scanWebRuntimeCoverageRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan web runtime coverage run row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate web runtime coverage runs: %w", err)
	}

	return items, nil
}

func (s *Store) CreateWebRuntimeCoverageRunForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.CreateWebRuntimeCoverageRunRequest) (models.WebRuntimeCoverageRun, error) {
	tenantID = strings.TrimSpace(tenantID)
	targetID = strings.TrimSpace(targetID)
	actor = strings.TrimSpace(actor)

	_, targetFound, err := s.GetWebTargetForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebRuntimeCoverageRun{}, err
	}
	if !targetFound {
		return models.WebRuntimeCoverageRun{}, ErrWebTargetNotFound
	}

	now := time.Now().UTC()
	item := models.WebRuntimeCoverageRun{
		ID:                          nextWebRuntimeCoverageRunID(),
		TenantID:                    tenantID,
		WebTargetID:                 targetID,
		ScanJobID:                   strings.TrimSpace(request.ScanJobID),
		RouteCoverage:               clampCoverage(request.RouteCoverage),
		APICoverage:                 clampCoverage(request.APICoverage),
		AuthCoverage:                clampCoverage(request.AuthCoverage),
		DiscoveredRouteCount:        request.DiscoveredRouteCount,
		DiscoveredAPIOperationCount: request.DiscoveredAPIOperationCount,
		DiscoveredAuthStateCount:    request.DiscoveredAuthStateCount,
		EvidenceRef:                 strings.TrimSpace(request.EvidenceRef),
		CreatedBy:                   actor,
		CreatedAt:                   now,
	}
	if item.CreatedBy == "" {
		item.CreatedBy = "system"
	}
	if item.DiscoveredRouteCount < 0 || item.DiscoveredAPIOperationCount < 0 || item.DiscoveredAuthStateCount < 0 {
		return models.WebRuntimeCoverageRun{}, fmt.Errorf("coverage discovered counts must be greater than or equal to zero")
	}

	return createWebRuntimeCoverageRunTx(ctx, s.pool, item)
}

func (s *Store) GetWebCoverageStatusForTenant(ctx context.Context, tenantID string, targetID string) (models.WebCoverageStatus, error) {
	tenantID = strings.TrimSpace(tenantID)
	targetID = strings.TrimSpace(targetID)
	status := models.WebCoverageStatus{
		WebTargetID:        targetID,
		RouteCoverageMeets: false,
		APICoverageMeets:   false,
		AuthCoverageMeets:  false,
		OverallMeets:       false,
	}

	_, targetFound, err := s.GetWebTargetForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebCoverageStatus{}, err
	}
	if !targetFound {
		return models.WebCoverageStatus{}, ErrWebTargetNotFound
	}

	baseline, baselineFound, err := s.GetWebCoverageBaselineForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebCoverageStatus{}, err
	}
	if baselineFound {
		status.Baseline = &baseline
	}

	runs, err := s.ListWebRuntimeCoverageRunsForTenant(ctx, tenantID, targetID, 1)
	if err != nil {
		return models.WebCoverageStatus{}, err
	}
	if len(runs) > 0 {
		status.LatestRun = &runs[0]
	}

	if status.Baseline == nil || status.LatestRun == nil {
		return status, nil
	}

	status.RouteCoverageMeets = status.LatestRun.RouteCoverage >= status.Baseline.MinimumRouteCoverage
	status.APICoverageMeets = status.LatestRun.APICoverage >= status.Baseline.MinimumAPICoverage
	status.AuthCoverageMeets = status.LatestRun.AuthCoverage >= status.Baseline.MinimumAuthCoverage
	status.OverallMeets = status.RouteCoverageMeets && status.APICoverageMeets && status.AuthCoverageMeets
	return status, nil
}

func (s *Store) EvaluateWebTargetScopeForTenant(ctx context.Context, tenantID string, targetID string, rawURL string) (models.WebTargetScopeEvaluation, error) {
	target, found, err := s.GetWebTargetForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebTargetScopeEvaluation{}, err
	}
	if !found {
		return models.WebTargetScopeEvaluation{}, ErrWebTargetNotFound
	}

	policy, _, err := s.GetWebCrawlPolicyForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebTargetScopeEvaluation{}, err
	}
	return evaluateWebTargetScope(target, policy, rawURL), nil
}

func (s *Store) RunWebTargetForTenant(ctx context.Context, tenantID string, targetID string, actor string, request models.RunWebTargetRequest) (models.WebTarget, models.ScanJob, bool, error) {
	target, found, err := s.GetWebTargetForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebTarget{}, models.ScanJob{}, false, err
	}
	if !found {
		return models.WebTarget{}, models.ScanJob{}, false, nil
	}

	policy, _, err := s.GetWebCrawlPolicyForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebTarget{}, models.ScanJob{}, true, err
	}
	baseline, hasBaseline, err := s.GetWebCoverageBaselineForTenant(ctx, tenantID, targetID)
	if err != nil {
		return models.WebTarget{}, models.ScanJob{}, true, err
	}

	profile := strings.TrimSpace(request.Profile)
	if profile == "" {
		profile = "runtime"
	}

	targetKind := "url"
	scanTarget := strings.TrimSpace(target.BaseURL)
	if strings.EqualFold(target.TargetType, "api") && strings.TrimSpace(target.APISchemaURL) != "" {
		targetKind = "api_schema"
		scanTarget = strings.TrimSpace(target.APISchemaURL)
	}
	if scanTarget == "" {
		return models.WebTarget{}, models.ScanJob{}, true, fmt.Errorf("web target does not contain a runnable url")
	}

	tools := sanitizeTools(request.Tools)
	if len(tools) == 0 {
		if targetKind == "api_schema" {
			tools = []string{"zap-api", "nuclei"}
		} else {
			tools = []string{"zap", "nuclei", "browser-probe"}
		}
	}
	if err := validateWebRuntimeTools(targetKind, policy.SafeMode, tools); err != nil {
		return models.WebTarget{}, models.ScanJob{}, true, err
	}

	taskLabels := map[string]string{
		"web_target_id":   strings.TrimSpace(target.ID),
		"web_target_type": strings.TrimSpace(target.TargetType),
		"web_safe_mode":   strconv.FormatBool(policy.SafeMode),
	}
	if strings.TrimSpace(policy.AuthProfileID) != "" {
		taskLabels["web_auth_profile_id"] = strings.TrimSpace(policy.AuthProfileID)
		authProfile, authProfileFound, err := s.GetWebAuthProfileForTenant(ctx, tenantID, policy.AuthProfileID)
		if err != nil {
			return models.WebTarget{}, models.ScanJob{}, true, err
		}
		if !authProfileFound {
			return models.WebTarget{}, models.ScanJob{}, true, ErrWebAuthProfileNotFound
		}
		if !authProfile.Enabled {
			return models.WebTarget{}, models.ScanJob{}, true, ErrWebAuthProfileDisabled
		}
		taskLabels["web_auth_type"] = strings.TrimSpace(authProfile.AuthType)
		if value := strings.TrimSpace(authProfile.LoginURL); value != "" {
			taskLabels["web_auth_login_url"] = value
		}
		if value := strings.TrimSpace(authProfile.CSRFMode); value != "" {
			taskLabels["web_auth_csrf_mode"] = value
		}
		if value := strings.TrimSpace(authProfile.TokenRefreshStrategy); value != "" {
			taskLabels["web_auth_token_refresh_strategy"] = value
		}
		if value := strings.TrimSpace(authProfile.UsernameSecretRef); value != "" {
			taskLabels["web_auth_username_secret_ref"] = value
		}
		if value := strings.TrimSpace(authProfile.PasswordSecretRef); value != "" {
			taskLabels["web_auth_password_secret_ref"] = value
		}
		if value := strings.TrimSpace(authProfile.BearerTokenSecretRef); value != "" {
			taskLabels["web_auth_bearer_token_secret_ref"] = value
		}
		if payload, ok := toCompactJSONLabel(authProfile.SessionBootstrap); ok {
			taskLabels["web_auth_session_bootstrap_json"] = payload
		}
		if payload, ok := toCompactJSONLabel(authProfile.TestPersonas); ok {
			taskLabels["web_auth_test_personas_json"] = payload
		}
	}
	if policy.MaxDepth > 0 {
		taskLabels["web_max_depth"] = fmt.Sprintf("%d", policy.MaxDepth)
	}
	if policy.MaxRequests > 0 {
		taskLabels["web_max_requests"] = fmt.Sprintf("%d", policy.MaxRequests)
	}
	if policy.RequestBudgetPerMinute > 0 {
		taskLabels["web_request_budget_per_minute"] = fmt.Sprintf("%d", policy.RequestBudgetPerMinute)
	}
	if len(policy.AllowPaths) > 0 {
		taskLabels["web_allow_paths"] = strings.Join(policy.AllowPaths, ",")
	}
	if len(policy.DenyPaths) > 0 {
		taskLabels["web_deny_paths"] = strings.Join(policy.DenyPaths, ",")
	}
	if len(policy.SeedURLs) > 0 {
		taskLabels["web_seed_urls"] = strings.Join(policy.SeedURLs, ",")
	}
	if hasBaseline {
		taskLabels["web_min_route_coverage"] = fmt.Sprintf("%.2f", baseline.MinimumRouteCoverage)
		taskLabels["web_min_api_coverage"] = fmt.Sprintf("%.2f", baseline.MinimumAPICoverage)
		taskLabels["web_min_auth_coverage"] = fmt.Sprintf("%.2f", baseline.MinimumAuthCoverage)
	}

	job, err := s.CreateForTenant(ctx, strings.TrimSpace(tenantID), models.CreateScanJobRequest{
		TenantID:    strings.TrimSpace(tenantID),
		TargetKind:  targetKind,
		Target:      scanTarget,
		Profile:     profile,
		RequestedBy: strings.TrimSpace(actor),
		Tools:       tools,
		TaskLabels:  taskLabels,
	})
	if err != nil {
		return models.WebTarget{}, models.ScanJob{}, true, err
	}

	return target, job, true, nil
}

func evaluateWebTargetScope(target models.WebTarget, policy models.WebCrawlPolicy, rawURL string) models.WebTargetScopeEvaluation {
	evaluation := models.WebTargetScopeEvaluation{
		WebTargetID: strings.TrimSpace(target.ID),
		URL:         strings.TrimSpace(rawURL),
		InScope:     false,
	}

	parsedURL, err := parseScopedURL(rawURL)
	if err != nil {
		evaluation.Reason = "url is invalid"
		return evaluation
	}

	baseURL, _ := parseScopedURL(target.BaseURL)
	if baseURL != nil && strings.TrimSpace(baseURL.Hostname()) != "" {
		if !strings.EqualFold(parsedURL.Hostname(), baseURL.Hostname()) {
			evaluation.Reason = "url host is out of scope for target base_url"
			return evaluation
		}
	}

	full := strings.ToLower(parsedURL.String())
	pathValue := strings.ToLower(parsedURL.EscapedPath())
	if pathValue == "" {
		pathValue = "/"
	}
	hostPath := strings.ToLower(parsedURL.Host + pathValue)

	denyPatterns := append([]string{}, target.OutOfScopePatterns...)
	denyPatterns = append(denyPatterns, policy.DenyPaths...)
	for _, pattern := range denyPatterns {
		if matchScopePattern(pattern, full, hostPath, pathValue) {
			evaluation.Reason = "matched deny pattern"
			return evaluation
		}
	}

	allowPatterns := append([]string{}, target.InScopePatterns...)
	allowPatterns = append(allowPatterns, policy.AllowPaths...)
	if len(allowPatterns) > 0 {
		for _, pattern := range allowPatterns {
			if matchScopePattern(pattern, full, hostPath, pathValue) {
				evaluation.InScope = true
				evaluation.Reason = "matched allow pattern"
				return evaluation
			}
		}
		evaluation.Reason = "no allow pattern matched"
		return evaluation
	}

	evaluation.InScope = true
	evaluation.Reason = "allowed by default target scope"
	return evaluation
}

func parseScopedURL(raw string) (*url.URL, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("url is required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		parsed, err = url.Parse("https://" + value)
		if err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return nil, fmt.Errorf("url host is required")
	}
	return parsed, nil
}

func validateWebRuntimeTools(targetKind string, safeMode bool, tools []string) error {
	kind := strings.ToLower(strings.TrimSpace(targetKind))
	if kind == "" {
		kind = "url"
	}

	baseAllowList := map[string]struct{}{
		"zap":           {},
		"zap-api":       {},
		"nuclei":        {},
		"browser-probe": {},
	}
	extendedAllowList := map[string]struct{}{
		"nmap":       {},
		"sqlmap":     {},
		"metasploit": {},
	}
	if kind == "api_schema" {
		delete(extendedAllowList, "nmap")
		delete(extendedAllowList, "metasploit")
	}

	for _, tool := range tools {
		normalizedTool := strings.ToLower(strings.TrimSpace(tool))
		if normalizedTool == "" {
			continue
		}
		if _, ok := baseAllowList[normalizedTool]; ok {
			continue
		}
		if !safeMode {
			if _, ok := extendedAllowList[normalizedTool]; ok {
				continue
			}
		}
		return fmt.Errorf("%w: %s for target_kind=%s safe_mode=%t", ErrWebRuntimeToolNotAllowed, normalizedTool, kind, safeMode)
	}
	return nil
}

func toCompactJSONLabel(value any) (string, bool) {
	if value == nil {
		return "", false
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	text := strings.TrimSpace(string(payload))
	if text == "" || text == "null" || text == "{}" || text == "[]" {
		return "", false
	}
	return text, true
}

func matchScopePattern(pattern string, full string, hostPath string, pathValue string) bool {
	needle := strings.ToLower(strings.TrimSpace(pattern))
	if needle == "" {
		return false
	}

	candidates := []string{full, hostPath, pathValue}
	if strings.HasPrefix(needle, "regex:") {
		expression := strings.TrimSpace(strings.TrimPrefix(needle, "regex:"))
		if expression == "" {
			return false
		}
		compiled, err := regexp.Compile(expression)
		if err != nil {
			return false
		}
		for _, candidate := range candidates {
			if compiled.MatchString(candidate) {
				return true
			}
		}
		return false
	}

	if strings.ContainsAny(needle, "*?[]") {
		for _, candidate := range candidates {
			ok, err := path.Match(needle, candidate)
			if err == nil && ok {
				return true
			}
		}
		return false
	}

	if strings.HasPrefix(needle, "/") {
		return strings.HasPrefix(pathValue, needle)
	}
	if strings.Contains(needle, "://") {
		return strings.HasPrefix(full, needle)
	}
	for _, candidate := range candidates {
		if strings.HasPrefix(candidate, needle) {
			return true
		}
	}
	return false
}

func scanWebTarget(row interface{ Scan(dest ...any) error }) (models.WebTarget, error) {
	var (
		item       models.WebTarget
		labelsJSON []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.Name,
		&item.TargetType,
		&item.BaseURL,
		&item.APISchemaURL,
		&item.InScopePatterns,
		&item.OutOfScopePatterns,
		&labelsJSON,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.WebTarget{}, err
	}
	if len(labelsJSON) > 0 {
		if err := json.Unmarshal(labelsJSON, &item.Labels); err != nil {
			return models.WebTarget{}, fmt.Errorf("decode web target labels: %w", err)
		}
	}
	if item.Labels == nil {
		item.Labels = map[string]any{}
	}
	item.TargetType = normalizeWebTargetType(item.TargetType)
	item.BaseURL = normalizeURLValue(item.BaseURL)
	item.APISchemaURL = normalizeURLValue(item.APISchemaURL)
	item.InScopePatterns = sanitizeStringList(item.InScopePatterns)
	item.OutOfScopePatterns = sanitizeStringList(item.OutOfScopePatterns)
	return item, nil
}

func scanWebAuthProfile(row interface{ Scan(dest ...any) error }) (models.WebAuthProfile, error) {
	var (
		item                 models.WebAuthProfile
		sessionBootstrapJSON []byte
		testPersonasJSON     []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.Name,
		&item.AuthType,
		&item.LoginURL,
		&item.UsernameSecretRef,
		&item.PasswordSecretRef,
		&item.BearerTokenSecretRef,
		&item.CSRFMode,
		&sessionBootstrapJSON,
		&testPersonasJSON,
		&item.TokenRefreshStrategy,
		&item.Enabled,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.WebAuthProfile{}, err
	}
	if len(sessionBootstrapJSON) > 0 {
		if err := json.Unmarshal(sessionBootstrapJSON, &item.SessionBootstrap); err != nil {
			return models.WebAuthProfile{}, fmt.Errorf("decode auth profile session bootstrap: %w", err)
		}
	}
	if len(testPersonasJSON) > 0 {
		if err := json.Unmarshal(testPersonasJSON, &item.TestPersonas); err != nil {
			return models.WebAuthProfile{}, fmt.Errorf("decode auth profile test personas: %w", err)
		}
	}
	if item.SessionBootstrap == nil {
		item.SessionBootstrap = map[string]any{}
	}
	if item.TestPersonas == nil {
		item.TestPersonas = []map[string]any{}
	}
	item.AuthType = normalizeAuthType(item.AuthType)
	item.CSRFMode = normalizeCSRFMode(item.CSRFMode)
	item.LoginURL = normalizeURLValue(item.LoginURL)
	return item, nil
}

func scanWebCrawlPolicy(row interface{ Scan(dest ...any) error }) (models.WebCrawlPolicy, error) {
	var (
		item        models.WebCrawlPolicy
		authProfile *string
		headersJSON []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.WebTargetID,
		&authProfile,
		&item.SafeMode,
		&item.MaxDepth,
		&item.MaxRequests,
		&item.RequestBudgetPerMinute,
		&item.AllowPaths,
		&item.DenyPaths,
		&item.SeedURLs,
		&headersJSON,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.WebCrawlPolicy{}, err
	}
	if authProfile != nil {
		item.AuthProfileID = strings.TrimSpace(*authProfile)
	}
	if len(headersJSON) > 0 {
		if err := json.Unmarshal(headersJSON, &item.Headers); err != nil {
			return models.WebCrawlPolicy{}, fmt.Errorf("decode crawl policy headers: %w", err)
		}
	}
	if item.Headers == nil {
		item.Headers = map[string]any{}
	}
	item.AllowPaths = sanitizeStringList(item.AllowPaths)
	item.DenyPaths = sanitizeStringList(item.DenyPaths)
	item.SeedURLs = sanitizeStringList(item.SeedURLs)
	if item.MaxDepth < 0 {
		item.MaxDepth = 0
	}
	if item.MaxRequests < 0 {
		item.MaxRequests = 0
	}
	if item.RequestBudgetPerMinute < 0 {
		item.RequestBudgetPerMinute = 0
	}
	return item, nil
}

func scanWebCoverageBaseline(row interface{ Scan(dest ...any) error }) (models.WebCoverageBaseline, error) {
	var item models.WebCoverageBaseline
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.WebTargetID,
		&item.ExpectedRouteCount,
		&item.ExpectedAPIOperationCount,
		&item.ExpectedAuthStateCount,
		&item.MinimumRouteCoverage,
		&item.MinimumAPICoverage,
		&item.MinimumAuthCoverage,
		&item.Notes,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.WebCoverageBaseline{}, err
	}
	if item.ExpectedRouteCount < 0 {
		item.ExpectedRouteCount = 0
	}
	if item.ExpectedAPIOperationCount < 0 {
		item.ExpectedAPIOperationCount = 0
	}
	if item.ExpectedAuthStateCount < 0 {
		item.ExpectedAuthStateCount = 0
	}
	item.MinimumRouteCoverage = clampCoverage(item.MinimumRouteCoverage)
	item.MinimumAPICoverage = clampCoverage(item.MinimumAPICoverage)
	item.MinimumAuthCoverage = clampCoverage(item.MinimumAuthCoverage)
	item.Notes = strings.TrimSpace(item.Notes)
	return item, nil
}

func scanWebRuntimeCoverageRun(row interface{ Scan(dest ...any) error }) (models.WebRuntimeCoverageRun, error) {
	var item models.WebRuntimeCoverageRun
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.WebTargetID,
		&item.ScanJobID,
		&item.RouteCoverage,
		&item.APICoverage,
		&item.AuthCoverage,
		&item.DiscoveredRouteCount,
		&item.DiscoveredAPIOperationCount,
		&item.DiscoveredAuthStateCount,
		&item.EvidenceRef,
		&item.CreatedBy,
		&item.CreatedAt,
	)
	if err != nil {
		return models.WebRuntimeCoverageRun{}, err
	}
	item.RouteCoverage = clampCoverage(item.RouteCoverage)
	item.APICoverage = clampCoverage(item.APICoverage)
	item.AuthCoverage = clampCoverage(item.AuthCoverage)
	if item.DiscoveredRouteCount < 0 {
		item.DiscoveredRouteCount = 0
	}
	if item.DiscoveredAPIOperationCount < 0 {
		item.DiscoveredAPIOperationCount = 0
	}
	if item.DiscoveredAuthStateCount < 0 {
		item.DiscoveredAuthStateCount = 0
	}
	item.ScanJobID = strings.TrimSpace(item.ScanJobID)
	item.EvidenceRef = strings.TrimSpace(item.EvidenceRef)
	item.CreatedBy = strings.TrimSpace(item.CreatedBy)
	return item, nil
}

func normalizeCreateWebTargetRequest(tenantID string, actor string, request models.CreateWebTargetRequest, now time.Time) models.WebTarget {
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = "Unnamed Web Target"
	}
	baseURL := normalizeURLValue(request.BaseURL)
	if actor == "" {
		actor = "system"
	}
	labels := request.Labels
	if labels == nil {
		labels = map[string]any{}
	}
	return models.WebTarget{
		ID:                 nextWebTargetID(),
		TenantID:           tenantID,
		Name:               name,
		TargetType:         normalizeWebTargetType(request.TargetType),
		BaseURL:            baseURL,
		APISchemaURL:       normalizeURLValue(request.APISchemaURL),
		InScopePatterns:    sanitizeStringList(request.InScopePatterns),
		OutOfScopePatterns: sanitizeStringList(request.OutOfScopePatterns),
		Labels:             labels,
		CreatedBy:          actor,
		UpdatedBy:          actor,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

func normalizeUpdateWebTargetRequest(existing models.WebTarget, actor string, request models.UpdateWebTargetRequest, now time.Time) models.WebTarget {
	name := strings.TrimSpace(request.Name)
	if name != "" {
		existing.Name = name
	}
	targetType := normalizeWebTargetType(request.TargetType)
	if targetType != "" {
		existing.TargetType = targetType
	}
	baseURL := normalizeURLValue(request.BaseURL)
	if baseURL != "" {
		existing.BaseURL = baseURL
	}
	if strings.TrimSpace(request.APISchemaURL) != "" {
		existing.APISchemaURL = normalizeURLValue(request.APISchemaURL)
	}
	if request.InScopePatterns != nil {
		existing.InScopePatterns = sanitizeStringList(request.InScopePatterns)
	}
	if request.OutOfScopePatterns != nil {
		existing.OutOfScopePatterns = sanitizeStringList(request.OutOfScopePatterns)
	}
	if request.Labels != nil {
		existing.Labels = request.Labels
	}
	if existing.Labels == nil {
		existing.Labels = map[string]any{}
	}
	if actor == "" {
		actor = existing.UpdatedBy
	}
	if actor == "" {
		actor = existing.CreatedBy
	}
	if actor == "" {
		actor = "system"
	}
	existing.UpdatedBy = actor
	existing.UpdatedAt = now
	return existing
}

func normalizeCreateWebAuthProfileRequest(tenantID string, actor string, request models.CreateWebAuthProfileRequest, now time.Time) models.WebAuthProfile {
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = "Unnamed Auth Profile"
	}
	if actor == "" {
		actor = "system"
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	sessionBootstrap := request.SessionBootstrap
	if sessionBootstrap == nil {
		sessionBootstrap = map[string]any{}
	}
	return models.WebAuthProfile{
		ID:                   nextWebAuthProfileID(),
		TenantID:             tenantID,
		Name:                 name,
		AuthType:             normalizeAuthType(request.AuthType),
		LoginURL:             normalizeURLValue(request.LoginURL),
		UsernameSecretRef:    strings.TrimSpace(request.UsernameSecretRef),
		PasswordSecretRef:    strings.TrimSpace(request.PasswordSecretRef),
		BearerTokenSecretRef: strings.TrimSpace(request.BearerTokenSecretRef),
		CSRFMode:             normalizeCSRFMode(request.CSRFMode),
		SessionBootstrap:     sessionBootstrap,
		TestPersonas:         sanitizePersonaList(request.TestPersonas),
		TokenRefreshStrategy: strings.TrimSpace(request.TokenRefreshStrategy),
		Enabled:              enabled,
		CreatedBy:            actor,
		UpdatedBy:            actor,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

func normalizeUpdateWebAuthProfileRequest(existing models.WebAuthProfile, actor string, request models.UpdateWebAuthProfileRequest, now time.Time) models.WebAuthProfile {
	if trimmed := strings.TrimSpace(request.Name); trimmed != "" {
		existing.Name = trimmed
	}
	if trimmed := strings.TrimSpace(request.AuthType); trimmed != "" {
		existing.AuthType = normalizeAuthType(trimmed)
	}
	if request.LoginURL != "" {
		existing.LoginURL = normalizeURLValue(request.LoginURL)
	}
	if request.UsernameSecretRef != "" {
		existing.UsernameSecretRef = strings.TrimSpace(request.UsernameSecretRef)
	}
	if request.PasswordSecretRef != "" {
		existing.PasswordSecretRef = strings.TrimSpace(request.PasswordSecretRef)
	}
	if request.BearerTokenSecretRef != "" {
		existing.BearerTokenSecretRef = strings.TrimSpace(request.BearerTokenSecretRef)
	}
	if trimmed := strings.TrimSpace(request.CSRFMode); trimmed != "" {
		existing.CSRFMode = normalizeCSRFMode(trimmed)
	}
	if request.SessionBootstrap != nil {
		existing.SessionBootstrap = request.SessionBootstrap
	}
	if request.TestPersonas != nil {
		existing.TestPersonas = sanitizePersonaList(request.TestPersonas)
	}
	if request.TokenRefreshStrategy != "" {
		existing.TokenRefreshStrategy = strings.TrimSpace(request.TokenRefreshStrategy)
	}
	if request.Enabled != nil {
		existing.Enabled = *request.Enabled
	}
	if existing.SessionBootstrap == nil {
		existing.SessionBootstrap = map[string]any{}
	}
	if existing.TestPersonas == nil {
		existing.TestPersonas = []map[string]any{}
	}
	if actor == "" {
		actor = existing.UpdatedBy
	}
	if actor == "" {
		actor = existing.CreatedBy
	}
	if actor == "" {
		actor = "system"
	}
	existing.UpdatedBy = actor
	existing.UpdatedAt = now
	return existing
}

func normalizeWebTargetType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "api":
		return "api"
	case "webapp", "":
		return "webapp"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeAuthType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "form":
		return "form"
	case "bearer", "cookie", "oidc", "saml", "apikey":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeCSRFMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return "auto"
	case "disabled", "header", "token":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeURLValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	if strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		parsed, err = url.Parse("https://" + trimmed)
		if err == nil && strings.TrimSpace(parsed.Host) != "" {
			return parsed.String()
		}
	}
	return parsed.String()
}

func sanitizeStringList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func sanitizePersonaList(values []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if len(value) == 0 {
			continue
		}
		copied := make(map[string]any, len(value))
		for key, entry := range value {
			normalizedKey := strings.TrimSpace(key)
			if normalizedKey == "" {
				continue
			}
			copied[normalizedKey] = entry
		}
		if len(copied) == 0 {
			continue
		}
		out = append(out, copied)
	}
	return out
}

func clampCoverage(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func nullableString(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func nextWebTargetID() string {
	sequence := atomic.AddUint64(&webTargetSequence, 1)
	return fmt.Sprintf("web-target-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextWebAuthProfileID() string {
	sequence := atomic.AddUint64(&webAuthProfileSequence, 1)
	return fmt.Sprintf("web-auth-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextWebCrawlPolicyID() string {
	sequence := atomic.AddUint64(&webCrawlPolicySequence, 1)
	return fmt.Sprintf("web-crawl-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextWebCoverageBaselineID() string {
	sequence := atomic.AddUint64(&webCoverageBaselineSequence, 1)
	return fmt.Sprintf("web-coverage-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextWebRuntimeCoverageRunID() string {
	sequence := atomic.AddUint64(&webRuntimeCoverageRunSequence, 1)
	return fmt.Sprintf("web-coverage-run-%d-%06d", time.Now().UTC().Unix(), sequence)
}
