package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/models"
)

var (
	authTokenSequence  uint64
	auditEventSequence uint64
)

func (s *Store) EnsureBootstrap(ctx context.Context, cfg config.Config) error {
	token := strings.TrimSpace(cfg.BootstrapAdminToken)
	if token == "" {
		return nil
	}

	orgSlug := normalizeSlug(cfg.BootstrapOrgSlug, "local")
	orgID := "bootstrap-org-" + orgSlug
	userID := "bootstrap-user-" + normalizeSlug(cfg.BootstrapAdminEmail, "admin")
	tokenID := "bootstrap-token-" + orgSlug
	now := time.Now().UTC()
	role := normalizeRole(cfg.BootstrapAdminRole)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO organizations (id, slug, name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $4)
		ON CONFLICT (id) DO UPDATE SET
			slug = EXCLUDED.slug,
			name = EXCLUDED.name,
			updated_at = EXCLUDED.updated_at
	`, orgID, orgSlug, strings.TrimSpace(cfg.BootstrapOrgName), now)
	if err != nil {
		return fmt.Errorf("upsert bootstrap organization: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO users (id, email, display_name, auth_provider, provider_subject, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6)
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			display_name = EXCLUDED.display_name,
			auth_provider = EXCLUDED.auth_provider,
			provider_subject = EXCLUDED.provider_subject,
			updated_at = EXCLUDED.updated_at
	`, userID, strings.TrimSpace(cfg.BootstrapAdminEmail), strings.TrimSpace(cfg.BootstrapAdminName), "local", strings.TrimSpace(cfg.BootstrapAdminEmail), now)
	if err != nil {
		return fmt.Errorf("upsert bootstrap user: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO memberships (user_id, organization_id, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $4)
		ON CONFLICT (user_id, organization_id) DO UPDATE SET
			role = EXCLUDED.role,
			updated_at = EXCLUDED.updated_at
	`, userID, orgID, role, now)
	if err != nil {
		return fmt.Errorf("upsert bootstrap membership: %w", err)
	}

	scopesJSON, err := json.Marshal([]string{"*"})
	if err != nil {
		return fmt.Errorf("marshal bootstrap scopes: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO api_tokens (
			id, organization_id, user_id, token_name, token_hash, scopes_json,
			disabled, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			FALSE, $7, $7
		)
		ON CONFLICT (id) DO UPDATE SET
			organization_id = EXCLUDED.organization_id,
			user_id = EXCLUDED.user_id,
			token_name = EXCLUDED.token_name,
			token_hash = EXCLUDED.token_hash,
			scopes_json = EXCLUDED.scopes_json,
			disabled = FALSE,
			updated_at = EXCLUDED.updated_at
	`, tokenID, orgID, userID, "bootstrap-admin", auth.TokenHash(token), scopesJSON, now)
	if err != nil {
		return fmt.Errorf("upsert bootstrap api token: %w", err)
	}

	return nil
}

func (s *Store) AuthenticateToken(ctx context.Context, rawToken string) (models.AuthPrincipal, bool, error) {
	tokenHash := auth.TokenHash(rawToken)

	row := s.pool.QueryRow(ctx, `
		SELECT
			u.id,
			o.id,
			o.slug,
			o.name,
			u.email,
			u.display_name,
			m.role,
			u.auth_provider,
			t.scopes_json
		FROM api_tokens t
		INNER JOIN organizations o ON o.id = t.organization_id
		INNER JOIN users u ON u.id = t.user_id
		INNER JOIN memberships m ON m.user_id = u.id AND m.organization_id = o.id
		WHERE t.token_hash = $1
		  AND t.disabled = FALSE
		  AND (t.expires_at IS NULL OR t.expires_at > NOW())
	`, tokenHash)

	var principal models.AuthPrincipal
	var scopesJSON []byte
	err := row.Scan(
		&principal.UserID,
		&principal.OrganizationID,
		&principal.OrganizationSlug,
		&principal.OrganizationName,
		&principal.Email,
		&principal.DisplayName,
		&principal.Role,
		&principal.AuthProvider,
		&scopesJSON,
	)
	if err != nil {
		if isNoRows(err) {
			return models.AuthPrincipal{}, false, nil
		}
		return models.AuthPrincipal{}, false, fmt.Errorf("authenticate token: %w", err)
	}

	if len(scopesJSON) > 0 {
		if err := json.Unmarshal(scopesJSON, &principal.Scopes); err != nil {
			return models.AuthPrincipal{}, false, fmt.Errorf("decode token scopes: %w", err)
		}
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE api_tokens
		SET last_used_at = $2,
		    updated_at = $2
		WHERE token_hash = $1
	`, tokenHash, time.Now().UTC())
	if err != nil {
		return models.AuthPrincipal{}, false, fmt.Errorf("touch api token: %w", err)
	}

	return principal, true, nil
}

func (s *Store) ListAPITokens(ctx context.Context, organizationID string, limit int) ([]models.APIToken, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, organization_id, user_id, token_name, scopes_json, disabled,
		       expires_at, last_used_at, created_at, updated_at
		FROM api_tokens
		WHERE organization_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()

	out := make([]models.APIToken, 0, limit)
	for rows.Next() {
		token, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate api tokens: %w", err)
	}

	return out, nil
}

func (s *Store) CreateAPIToken(ctx context.Context, principal models.AuthPrincipal, request models.CreateAPITokenRequest) (models.CreatedAPIToken, error) {
	now := time.Now().UTC()
	scopes, err := auth.NormalizeRequestedScopes(principal.Role, request.Scopes)
	if err != nil {
		return models.CreatedAPIToken{}, fmt.Errorf("normalize api token scopes: %w", err)
	}

	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return models.CreatedAPIToken{}, fmt.Errorf("marshal api token scopes: %w", err)
	}

	plaintextToken, err := generatePlaintextToken()
	if err != nil {
		return models.CreatedAPIToken{}, fmt.Errorf("generate api token: %w", err)
	}

	token := models.APIToken{
		ID:             nextAPITokenID(),
		OrganizationID: principal.OrganizationID,
		UserID:         principal.UserID,
		TokenName:      strings.TrimSpace(request.TokenName),
		Scopes:         scopes,
		Disabled:       false,
		ExpiresAt:      request.ExpiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO api_tokens (
			id, organization_id, user_id, token_name, token_hash, scopes_json,
			disabled, expires_at, last_used_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			FALSE, $7, NULL, $8, $8
		)
	`, token.ID, token.OrganizationID, token.UserID, token.TokenName, auth.TokenHash(plaintextToken), scopesJSON, token.ExpiresAt, now)
	if err != nil {
		return models.CreatedAPIToken{}, fmt.Errorf("insert api token: %w", err)
	}

	return models.CreatedAPIToken{
		Token:          token,
		PlaintextToken: plaintextToken,
	}, nil
}

func (s *Store) DisableAPIToken(ctx context.Context, organizationID string, tokenID string) (models.APIToken, bool, error) {
	if strings.HasPrefix(strings.TrimSpace(tokenID), "bootstrap-token-") {
		return models.APIToken{}, false, ErrProtectedToken
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.APIToken{}, false, fmt.Errorf("begin disable api token tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		SELECT id, organization_id, user_id, token_name, scopes_json, disabled,
		       expires_at, last_used_at, created_at, updated_at
		FROM api_tokens
		WHERE id = $1
		  AND organization_id = $2
		FOR UPDATE
	`, strings.TrimSpace(tokenID), strings.TrimSpace(organizationID))

	token, err := scanAPIToken(row)
	if err != nil {
		if isNoRows(err) {
			return models.APIToken{}, false, nil
		}
		return models.APIToken{}, false, err
	}

	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
		UPDATE api_tokens
		SET disabled = TRUE,
		    updated_at = $3
		WHERE id = $1
		  AND organization_id = $2
	`, token.ID, token.OrganizationID, now)
	if err != nil {
		return models.APIToken{}, false, fmt.Errorf("disable api token: %w", err)
	}

	token.Disabled = true
	token.UpdatedAt = now

	if err := tx.Commit(ctx); err != nil {
		return models.APIToken{}, false, fmt.Errorf("commit disable api token tx: %w", err)
	}

	return token, true, nil
}

func (s *Store) RecordAuditEvent(ctx context.Context, event models.AuditEvent) error {
	now := event.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if event.ID == "" {
		event.ID = nextAuditEventID()
	}

	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_events (
			id, organization_id, actor_user_id, actor_email, action, resource_type, resource_id,
			status, request_method, request_path, remote_addr, details_json, created_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13
		)
	`, event.ID, event.OrganizationID, event.ActorUserID, event.ActorEmail, event.Action, event.ResourceType, event.ResourceID,
		event.Status, event.RequestMethod, event.RequestPath, event.RemoteAddr, detailsJSON, now)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}

	return nil
}

func (s *Store) ListAuditEvents(ctx context.Context, organizationID string, limit int) ([]models.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, organization_id, actor_user_id, actor_email, action, resource_type, resource_id,
		       status, request_method, request_path, remote_addr, details_json, created_at
		FROM audit_events
		WHERE organization_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, strings.TrimSpace(organizationID), limit)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	out := make([]models.AuditEvent, 0, limit)
	for rows.Next() {
		var event models.AuditEvent
		var detailsJSON []byte

		if err := rows.Scan(
			&event.ID,
			&event.OrganizationID,
			&event.ActorUserID,
			&event.ActorEmail,
			&event.Action,
			&event.ResourceType,
			&event.ResourceID,
			&event.Status,
			&event.RequestMethod,
			&event.RequestPath,
			&event.RemoteAddr,
			&detailsJSON,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}

		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &event.Details); err != nil {
				return nil, fmt.Errorf("unmarshal audit details: %w", err)
			}
		}

		out = append(out, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}

	return out, nil
}

func nextAPITokenID() string {
	sequence := atomic.AddUint64(&authTokenSequence, 1)
	return fmt.Sprintf("token-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextAuditEventID() string {
	sequence := atomic.AddUint64(&auditEventSequence, 1)
	return fmt.Sprintf("audit-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func normalizeSlug(value string, fallback string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		normalized = fallback
	}
	replacer := strings.NewReplacer("@", "-", ".", "-", "_", "-", " ", "-")
	normalized = replacer.Replace(normalized)
	normalized = strings.Trim(normalized, "-")
	if normalized == "" {
		return fallback
	}
	return normalized
}

func normalizeRole(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case auth.RoleAppSecAdmin:
		return auth.RoleAppSecAdmin
	case auth.RoleDeveloper:
		return auth.RoleDeveloper
	case auth.RoleViewer:
		return auth.RoleViewer
	default:
		return auth.RolePlatformAdmin
	}
}

func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

type apiTokenScanner interface {
	Scan(dest ...any) error
}

func scanAPIToken(scanner apiTokenScanner) (models.APIToken, error) {
	var token models.APIToken
	var scopesJSON []byte

	err := scanner.Scan(
		&token.ID,
		&token.OrganizationID,
		&token.UserID,
		&token.TokenName,
		&scopesJSON,
		&token.Disabled,
		&token.ExpiresAt,
		&token.LastUsedAt,
		&token.CreatedAt,
		&token.UpdatedAt,
	)
	if err != nil {
		if isNoRows(err) {
			return models.APIToken{}, err
		}
		return models.APIToken{}, fmt.Errorf("scan api token: %w", err)
	}

	if len(scopesJSON) > 0 {
		if err := json.Unmarshal(scopesJSON, &token.Scopes); err != nil {
			return models.APIToken{}, fmt.Errorf("decode api token scopes: %w", err)
		}
	}

	return token, nil
}

func generatePlaintextToken() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}

	return "uss_" + hex.EncodeToString(raw[:]), nil
}
