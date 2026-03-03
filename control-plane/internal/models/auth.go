package models

import "time"

type AuthPrincipal struct {
	UserID           string   `json:"user_id"`
	OrganizationID   string   `json:"organization_id"`
	OrganizationSlug string   `json:"organization_slug"`
	OrganizationName string   `json:"organization_name"`
	Email            string   `json:"email"`
	DisplayName      string   `json:"display_name"`
	Role             string   `json:"role"`
	AuthProvider     string   `json:"auth_provider"`
	Scopes           []string `json:"scopes,omitempty"`
}

type AuthSession struct {
	Principal      AuthPrincipal `json:"principal"`
	SSOEnabled     bool          `json:"sso_enabled"`
	OIDCIssuerURL  string        `json:"oidc_issuer_url,omitempty"`
	OIDCClientID   string        `json:"oidc_client_id,omitempty"`
	BootstrapToken bool          `json:"bootstrap_token"`
}

type APIToken struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	UserID         string     `json:"user_id"`
	TokenName      string     `json:"token_name"`
	Scopes         []string   `json:"scopes,omitempty"`
	Disabled       bool       `json:"disabled"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type CreateAPITokenRequest struct {
	TokenName string     `json:"token_name"`
	Scopes    []string   `json:"scopes,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type CreatedAPIToken struct {
	Token          APIToken `json:"token"`
	PlaintextToken string   `json:"plaintext_token"`
}

type AuditEvent struct {
	ID             string         `json:"id"`
	OrganizationID string         `json:"organization_id"`
	ActorUserID    string         `json:"actor_user_id,omitempty"`
	ActorEmail     string         `json:"actor_email,omitempty"`
	Action         string         `json:"action"`
	ResourceType   string         `json:"resource_type"`
	ResourceID     string         `json:"resource_id,omitempty"`
	Status         string         `json:"status"`
	RequestMethod  string         `json:"request_method,omitempty"`
	RequestPath    string         `json:"request_path,omitempty"`
	RemoteAddr     string         `json:"remote_addr,omitempty"`
	Details        map[string]any `json:"details,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}
