package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/models"
)

type stubAPIStore struct {
	authPrincipal    models.AuthPrincipal
	authenticated    bool
	authErr          error
	auditEvents      []models.AuditEvent
	apiTokens        []models.APIToken
	registerResponse models.WorkerRegistrationResponse
}

func (s *stubAPIStore) Ping(context.Context) error {
	return nil
}

func (s *stubAPIStore) AuthenticateToken(context.Context, string) (models.AuthPrincipal, bool, error) {
	return s.authPrincipal, s.authenticated, s.authErr
}

func (s *stubAPIStore) RecordAuditEvent(_ context.Context, event models.AuditEvent) error {
	s.auditEvents = append(s.auditEvents, event)
	return nil
}

func (s *stubAPIStore) ListAuditEvents(context.Context, string, int) ([]models.AuditEvent, error) {
	return s.auditEvents, nil
}

func (s *stubAPIStore) ListAPITokens(context.Context, string, int) ([]models.APIToken, error) {
	return s.apiTokens, nil
}

func (s *stubAPIStore) CreateAPIToken(context.Context, models.AuthPrincipal, models.CreateAPITokenRequest) (models.CreatedAPIToken, error) {
	return models.CreatedAPIToken{}, nil
}

func (s *stubAPIStore) DisableAPIToken(context.Context, string, string) (models.APIToken, bool, error) {
	return models.APIToken{}, false, nil
}

func (s *stubAPIStore) ListForTenant(context.Context, string, int) ([]models.ScanJob, error) {
	return nil, nil
}

func (s *stubAPIStore) CreateForTenant(context.Context, string, models.CreateScanJobRequest) (models.ScanJob, error) {
	return models.ScanJob{}, nil
}

func (s *stubAPIStore) GetForTenant(context.Context, string, string) (models.ScanJob, bool, error) {
	return models.ScanJob{}, false, nil
}

func (s *stubAPIStore) RegisterWorker(context.Context, models.WorkerRegistrationRequest) (models.WorkerRegistrationResponse, error) {
	return s.registerResponse, nil
}

func (s *stubAPIStore) RecordHeartbeat(context.Context, models.HeartbeatRequest) (models.HeartbeatResponse, error) {
	return models.HeartbeatResponse{}, nil
}

func (s *stubAPIStore) ListFindingsForTenant(context.Context, string, int) ([]models.CanonicalFinding, error) {
	return nil, nil
}

func (s *stubAPIStore) ListAssetsForTenant(context.Context, string, int) ([]models.AssetSummary, error) {
	return nil, nil
}

func (s *stubAPIStore) ListPoliciesForTenant(context.Context, string, int) ([]models.Policy, error) {
	return nil, nil
}

func (s *stubAPIStore) CreatePolicyForTenant(context.Context, string, models.CreatePolicyRequest) (models.Policy, error) {
	return models.Policy{}, nil
}

func (s *stubAPIStore) ListRemediationsForTenant(context.Context, string, int) ([]models.RemediationAction, error) {
	return nil, nil
}

func (s *stubAPIStore) CreateRemediationForTenant(context.Context, string, models.CreateRemediationRequest) (models.RemediationAction, error) {
	return models.RemediationAction{}, nil
}

func TestAuthSessionRequiresBearerToken(t *testing.T) {
	t.Parallel()

	server := New(config.Load(), &stubAPIStore{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}

	var response models.APIError
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode api error: %v", err)
	}
	if response.Code != "missing_bearer_token" {
		t.Fatalf("unexpected error code: %s", response.Code)
	}
}

func TestAuthSessionReturnsPrincipal(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "bootstrap-user-admin-local",
			OrganizationID:   "bootstrap-org-local",
			OrganizationSlug: "local",
			OrganizationName: "Local Organization",
			Email:            "admin@local",
			DisplayName:      "Local Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}

	cfg := config.Load()
	cfg.OIDCIssuerURL = "https://issuer.example.com"
	cfg.OIDCClientID = "uss-control-plane"

	server := New(cfg, store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	request.Header.Set("Authorization", "Bearer uss-local-admin-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var session models.AuthSession
	if err := json.NewDecoder(recorder.Body).Decode(&session); err != nil {
		t.Fatalf("decode auth session: %v", err)
	}
	if session.Principal.Email != "admin@local" {
		t.Fatalf("unexpected principal email: %s", session.Principal.Email)
	}
	if !session.BootstrapToken {
		t.Fatal("expected bootstrap token session to be identified")
	}
	if !session.SSOEnabled {
		t.Fatal("expected oidc-ready config to be surfaced")
	}
	if len(store.auditEvents) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(store.auditEvents))
	}
}

func TestAuthTokenScopesEnforced(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "appsec@example.com",
			DisplayName:      "AppSec",
			Role:             "appsec_admin",
			AuthProvider:     "local",
			Scopes:           []string{"scan_jobs:read"},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/tokens", nil)
	request.Header.Set("Authorization", "Bearer dev-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
	if len(store.auditEvents) != 1 {
		t.Fatalf("expected denied request to be audited, got %d events", len(store.auditEvents))
	}
	if store.auditEvents[0].Status != "denied" {
		t.Fatalf("unexpected audit status: %s", store.auditEvents[0].Status)
	}
	if reason, ok := store.auditEvents[0].Details["reason"].(string); !ok || reason != "scope" {
		t.Fatalf("unexpected audit denial reason: %#v", store.auditEvents[0].Details["reason"])
	}
}

func TestWorkerSecretRequiredForRestRegistration(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		registerResponse: models.WorkerRegistrationResponse{
			Accepted:                 true,
			LeaseID:                  "lease-1",
			HeartbeatIntervalSeconds: 30,
		},
	}

	cfg := config.Load()
	cfg.WorkerSharedSecret = "phase1-worker-secret"

	server := New(cfg, store)
	body := `{"worker_id":"worker-1","worker_version":"1.0.0","operating_system":"windows","hostname":"host-1","capabilities":[]}`

	unauthorizedRecorder := httptest.NewRecorder()
	unauthorizedRequest := httptest.NewRequest(http.MethodPost, "/v1/workers/register", strings.NewReader(body))
	server.httpServer.Handler.ServeHTTP(unauthorizedRecorder, unauthorizedRequest)
	if unauthorizedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without worker secret, got %d", unauthorizedRecorder.Code)
	}

	authorizedRecorder := httptest.NewRecorder()
	authorizedRequest := httptest.NewRequest(http.MethodPost, "/v1/workers/register", strings.NewReader(body))
	authorizedRequest.Header.Set("Content-Type", "application/json")
	authorizedRequest.Header.Set("X-USS-Worker-Secret", "phase1-worker-secret")

	server.httpServer.Handler.ServeHTTP(authorizedRecorder, authorizedRequest)
	if authorizedRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 with worker secret, got %d", authorizedRecorder.Code)
	}

	var response models.WorkerRegistrationResponse
	if err := json.NewDecoder(authorizedRecorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode worker registration response: %v", err)
	}
	if !response.Accepted {
		t.Fatal("expected worker registration to be accepted")
	}
}

func TestAuthTokenCreateRejectsExpiredTimestamp(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "admin@example.com",
			DisplayName:      "Admin",
			Role:             "platform_admin",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/tokens", strings.NewReader(`{
		"token_name": "expired",
		"expires_at": "`+time.Now().UTC().Add(-1*time.Minute).Format(time.RFC3339)+`"
	}`))
	request.Header.Set("Authorization", "Bearer admin-token")
	request.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
}
