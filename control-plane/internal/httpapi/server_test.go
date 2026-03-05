package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

type stubAPIStore struct {
	authPrincipal            models.AuthPrincipal
	authenticated            bool
	authErr                  error
	createScanJobErr         error
	auditEvents              []models.AuditEvent
	apiTokens                []models.APIToken
	assetProfile             models.AssetProfile
	assetSummaries           []models.AssetSummary
	assetControls            []models.CompensatingControl
	syncedAssets             models.SyncAssetProfilesResult
	findingWaivers           []models.FindingWaiver
	riskSummary              models.RiskSummary
	remediation              models.RemediationAction
	remediationActivities    []models.RemediationActivity
	remediationEvidence      []models.RemediationEvidence
	remediationAssignments   []models.RemediationAssignmentRequest
	remediationVerifications []models.RemediationVerification
	remediationExceptions    []models.RemediationException
	remediationTickets       []models.RemediationTicketLink
	notifications            []models.NotificationEvent
	notificationSweep        models.NotificationSweepResult
	policy                   models.Policy
	policies                 []models.Policy
	policyVersions           []models.PolicyVersion
	policyApprovals          []models.PolicyApproval
	scanJob                  models.ScanJob
	createdOIDC              models.CreatedAPIToken
	oidcProvider             string
	oidcSubject              string
	oidcEmail                string
	oidcDisplayName          string
	registerResponse         models.WorkerRegistrationResponse
}

func (s *stubAPIStore) Ping(context.Context) error {
	return nil
}

func (s *stubAPIStore) AuthenticateToken(context.Context, string) (models.AuthPrincipal, bool, error) {
	return s.authPrincipal, s.authenticated, s.authErr
}

func (s *stubAPIStore) CreateOIDCSession(_ context.Context, provider string, subject string, email string, displayName string) (models.CreatedAPIToken, error) {
	s.oidcProvider = provider
	s.oidcSubject = subject
	s.oidcEmail = email
	s.oidcDisplayName = displayName
	return s.createdOIDC, nil
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
	if s.createScanJobErr != nil {
		return models.ScanJob{}, s.createScanJobErr
	}
	return s.scanJob, nil
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

func (s *stubAPIStore) ListFindingWaiversForTenant(context.Context, string, string, int) ([]models.FindingWaiver, error) {
	return s.findingWaivers, nil
}

func (s *stubAPIStore) CreateFindingWaiverForTenant(context.Context, string, string, models.CreateFindingWaiverRequest) (models.FindingWaiver, error) {
	if len(s.findingWaivers) == 0 {
		return models.FindingWaiver{}, nil
	}
	return s.findingWaivers[0], nil
}

func (s *stubAPIStore) ListRiskSummaryForTenant(context.Context, string) (models.RiskSummary, error) {
	return s.riskSummary, nil
}

func (s *stubAPIStore) ListAssetsForTenant(context.Context, string, int) ([]models.AssetSummary, error) {
	return s.assetSummaries, nil
}

func (s *stubAPIStore) GetAssetProfileForTenant(context.Context, string, string) (models.AssetProfile, bool, error) {
	if s.assetProfile.AssetID == "" {
		return models.AssetProfile{}, false, nil
	}
	return s.assetProfile, true, nil
}

func (s *stubAPIStore) UpsertAssetProfileForTenant(context.Context, string, string, models.UpsertAssetProfileRequest) (models.AssetProfile, error) {
	return s.assetProfile, nil
}

func (s *stubAPIStore) SyncAssetProfilesForTenant(context.Context, string, models.SyncAssetProfilesRequest) (models.SyncAssetProfilesResult, error) {
	return s.syncedAssets, nil
}

func (s *stubAPIStore) ListCompensatingControlsForTenant(context.Context, string, string, int) ([]models.CompensatingControl, error) {
	return s.assetControls, nil
}

func (s *stubAPIStore) CreateCompensatingControlForTenant(context.Context, string, string, models.CreateCompensatingControlRequest) (models.CompensatingControl, error) {
	if len(s.assetControls) == 0 {
		return models.CompensatingControl{}, nil
	}
	return s.assetControls[0], nil
}

func (s *stubAPIStore) ListPoliciesForTenant(context.Context, string, int) ([]models.Policy, error) {
	return s.policies, nil
}

func (s *stubAPIStore) GetPolicyForTenant(context.Context, string, string) (models.Policy, bool, error) {
	if s.policy.ID == "" {
		return models.Policy{}, false, nil
	}
	return s.policy, true, nil
}

func (s *stubAPIStore) CreatePolicyForTenant(context.Context, string, models.CreatePolicyRequest) (models.Policy, error) {
	return s.policy, nil
}

func (s *stubAPIStore) UpdatePolicyForTenant(context.Context, string, string, models.UpdatePolicyRequest) (models.Policy, bool, error) {
	if s.policy.ID == "" {
		return models.Policy{}, false, nil
	}
	return s.policy, true, nil
}

func (s *stubAPIStore) ListPolicyVersionsForTenant(context.Context, string, string, int) ([]models.PolicyVersion, error) {
	return s.policyVersions, nil
}

func (s *stubAPIStore) RollbackPolicyForTenant(context.Context, string, string, int64, string) (models.Policy, bool, error) {
	if s.policy.ID == "" {
		return models.Policy{}, false, nil
	}
	return s.policy, true, nil
}

func (s *stubAPIStore) ListPolicyApprovalsForTenant(context.Context, string, int) ([]models.PolicyApproval, error) {
	return s.policyApprovals, nil
}

func (s *stubAPIStore) DecidePolicyApproval(context.Context, string, string, bool, string, string) (models.PolicyApproval, bool, error) {
	if len(s.policyApprovals) == 0 {
		return models.PolicyApproval{}, false, nil
	}
	return s.policyApprovals[0], true, nil
}

func (s *stubAPIStore) ListRemediationsForTenant(context.Context, string, int) ([]models.RemediationAction, error) {
	if s.remediation.ID == "" {
		return nil, nil
	}
	return []models.RemediationAction{s.remediation}, nil
}

func (s *stubAPIStore) GetRemediationForTenant(context.Context, string, string) (models.RemediationAction, bool, error) {
	if s.remediation.ID == "" {
		return models.RemediationAction{}, false, nil
	}
	return s.remediation, true, nil
}

func (s *stubAPIStore) CreateRemediationForTenant(context.Context, string, models.CreateRemediationRequest) (models.RemediationAction, error) {
	return s.remediation, nil
}

func (s *stubAPIStore) TransitionRemediationForTenant(context.Context, string, string, models.TransitionRemediationRequest) (models.RemediationAction, bool, error) {
	if s.remediation.ID == "" {
		return models.RemediationAction{}, false, nil
	}
	return s.remediation, true, nil
}

func (s *stubAPIStore) ListRemediationActivityForTenant(context.Context, string, string, int) ([]models.RemediationActivity, error) {
	return s.remediationActivities, nil
}

func (s *stubAPIStore) CreateRemediationCommentForTenant(context.Context, string, string, string, models.CreateRemediationCommentRequest) (models.RemediationActivity, error) {
	if len(s.remediationActivities) == 0 {
		return models.RemediationActivity{}, nil
	}
	return s.remediationActivities[0], nil
}

func (s *stubAPIStore) ListRemediationEvidenceForTenant(context.Context, string, string, int) ([]models.RemediationEvidence, error) {
	return s.remediationEvidence, nil
}

func (s *stubAPIStore) CreateRemediationEvidenceForTenant(context.Context, string, string, string, models.CreateRemediationEvidenceRequest) (models.RemediationEvidence, error) {
	if len(s.remediationEvidence) == 0 {
		return models.RemediationEvidence{}, nil
	}
	return s.remediationEvidence[0], nil
}

func (s *stubAPIStore) ListRemediationVerificationsForTenant(context.Context, string, string, int) ([]models.RemediationVerification, error) {
	return s.remediationVerifications, nil
}

func (s *stubAPIStore) RequestRemediationRetestForTenant(context.Context, string, string, string, models.CreateRetestRequest) (models.RemediationVerification, models.ScanJob, error) {
	var verification models.RemediationVerification
	if len(s.remediationVerifications) > 0 {
		verification = s.remediationVerifications[0]
	}
	return verification, s.scanJob, nil
}

func (s *stubAPIStore) RecordRemediationVerificationForTenant(context.Context, string, string, string, models.RecordRemediationVerificationRequest) (models.RemediationVerification, bool, error) {
	if len(s.remediationVerifications) == 0 {
		return models.RemediationVerification{}, false, nil
	}
	return s.remediationVerifications[0], true, nil
}

func (s *stubAPIStore) ListRemediationExceptionsForTenant(context.Context, string, string, int) ([]models.RemediationException, error) {
	return s.remediationExceptions, nil
}

func (s *stubAPIStore) CreateRemediationExceptionForTenant(context.Context, string, string, string, models.CreateRemediationExceptionRequest) (models.RemediationException, error) {
	if len(s.remediationExceptions) == 0 {
		return models.RemediationException{}, nil
	}
	return s.remediationExceptions[0], nil
}

func (s *stubAPIStore) DecideRemediationExceptionForTenant(context.Context, string, string, bool, string, string) (models.RemediationException, bool, error) {
	if len(s.remediationExceptions) == 0 {
		return models.RemediationException{}, false, nil
	}
	return s.remediationExceptions[0], true, nil
}

func (s *stubAPIStore) ListRemediationTicketLinksForTenant(context.Context, string, string, int) ([]models.RemediationTicketLink, error) {
	return s.remediationTickets, nil
}

func (s *stubAPIStore) CreateRemediationTicketLinkForTenant(context.Context, string, string, models.CreateRemediationTicketLinkRequest) (models.RemediationTicketLink, error) {
	if len(s.remediationTickets) == 0 {
		return models.RemediationTicketLink{}, nil
	}
	return s.remediationTickets[0], nil
}

func (s *stubAPIStore) SyncRemediationTicketLinkForTenant(context.Context, string, string, string, models.SyncRemediationTicketLinkRequest) (models.RemediationTicketLink, bool, error) {
	if len(s.remediationTickets) == 0 {
		return models.RemediationTicketLink{}, false, nil
	}
	return s.remediationTickets[0], true, nil
}

func (s *stubAPIStore) ListRemediationAssignmentRequestsForTenant(context.Context, string, string, int) ([]models.RemediationAssignmentRequest, error) {
	return s.remediationAssignments, nil
}

func (s *stubAPIStore) CreateRemediationAssignmentRequestForTenant(context.Context, string, string, string, models.CreateRemediationAssignmentRequest) (models.RemediationAssignmentRequest, error) {
	if len(s.remediationAssignments) == 0 {
		return models.RemediationAssignmentRequest{}, nil
	}
	return s.remediationAssignments[0], nil
}

func (s *stubAPIStore) DecideRemediationAssignmentRequestForTenant(context.Context, string, string, bool, string, string) (models.RemediationAssignmentRequest, bool, error) {
	if len(s.remediationAssignments) == 0 {
		return models.RemediationAssignmentRequest{}, false, nil
	}
	return s.remediationAssignments[0], true, nil
}

func (s *stubAPIStore) ListNotificationEventsForTenant(context.Context, string, int) ([]models.NotificationEvent, error) {
	return s.notifications, nil
}

func (s *stubAPIStore) AcknowledgeNotificationEventForTenant(context.Context, string, string, string) (models.NotificationEvent, bool, error) {
	if len(s.notifications) == 0 {
		return models.NotificationEvent{}, false, nil
	}
	return s.notifications[0], true, nil
}

func (s *stubAPIStore) SweepRemediationEscalationsForTenant(context.Context, string, string) (models.NotificationSweepResult, error) {
	return s.notificationSweep, nil
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
	if response.Code != "authentication_required" {
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
	cfg.OIDCClientSecret = "test-secret"
	cfg.OIDCRedirectURL = "http://127.0.0.1:18083/auth/oidc/callback"

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

func TestScanJobPolicyDeniedReturnsForbidden(t *testing.T) {
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
			Scopes:           []string{"*"},
		},
		createScanJobErr: &jobs.PolicyDeniedError{
			PolicyID: "policy-1",
			Reason:   "requested tool is blocked by enforced policy",
			RuleHits: []string{"block_tool:metasploit"},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/scan-jobs", strings.NewReader(`{
		"target_kind": "domain",
		"target": "example.com",
		"profile": "default",
		"tools": ["metasploit"]
	}`))
	request.Header.Set("Authorization", "Bearer appsec-token")
	request.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}

func TestGlobalPolicyCreateRequiresPlatformAdmin(t *testing.T) {
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
			Scopes:           []string{"*"},
		},
	}

	server := New(config.Load(), store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/policies", strings.NewReader(`{
		"name": "Global Runtime Guardrail",
		"global": true,
		"mode": "enforce",
		"rules": ["require_approval:metasploit"]
	}`))
	request.Header.Set("Authorization", "Bearer appsec-token")
	request.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}

func TestAssetRouteSupportsProfilesAndControls(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
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
			Scopes:           []string{"*"},
		},
		assetProfile: models.AssetProfile{
			TenantID:    "org-1",
			AssetID:     "public.example.com",
			AssetType:   "domain",
			AssetName:   "public.example.com",
			Environment: "production",
			Exposure:    "internet",
			Criticality: 9,
			OwnerTeam:   "edge",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		assetControls: []models.CompensatingControl{
			{
				ID:            "control-1",
				AssetID:       "public.example.com",
				Name:          "WAF",
				ControlType:   "waf",
				ScopeLayer:    "dast",
				Effectiveness: 8,
				Enabled:       true,
				CreatedAt:     now,
				UpdatedAt:     now,
			},
		},
	}

	server := New(config.Load(), store)

	profileRecorder := httptest.NewRecorder()
	profileRequest := httptest.NewRequest(http.MethodPut, "/v1/assets/public.example.com", strings.NewReader(`{
		"asset_type": "domain",
		"asset_name": "public.example.com",
		"environment": "production",
		"exposure": "internet",
		"criticality": 9,
		"owner_team": "edge"
	}`))
	profileRequest.Header.Set("Authorization", "Bearer appsec-token")
	profileRequest.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(profileRecorder, profileRequest)
	if profileRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for asset profile upsert, got %d", profileRecorder.Code)
	}

	controlsRecorder := httptest.NewRecorder()
	controlsRequest := httptest.NewRequest(http.MethodGet, "/v1/assets/public.example.com/controls", nil)
	controlsRequest.Header.Set("Authorization", "Bearer appsec-token")

	server.httpServer.Handler.ServeHTTP(controlsRecorder, controlsRequest)
	if controlsRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for control list, got %d", controlsRecorder.Code)
	}
}

func TestRemediationRouteSupportsEvidence(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
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
			Scopes:           []string{"*"},
		},
		remediation: models.RemediationAction{
			ID:        "remediation-1",
			TenantID:  "org-1",
			FindingID: "finding-1",
			Title:     "Fix auth issue",
			Status:    "open",
			Owner:     "edge",
			CreatedAt: now,
			UpdatedAt: now,
		},
		remediationEvidence: []models.RemediationEvidence{
			{
				ID:            "evidence-1",
				RemediationID: "remediation-1",
				Kind:          "ticket",
				Ref:           "local://evidence/1",
				CreatedAt:     now,
				UpdatedAt:     now,
			},
		},
	}

	server := New(config.Load(), store)

	createRecorder := httptest.NewRecorder()
	createRequest := httptest.NewRequest(http.MethodPost, "/v1/remediations/remediation-1/evidence", strings.NewReader(`{
		"kind": "ticket",
		"ref": "local://evidence/1"
	}`))
	createRequest.Header.Set("Authorization", "Bearer appsec-token")
	createRequest.Header.Set("Content-Type", "application/json")

	server.httpServer.Handler.ServeHTTP(createRecorder, createRequest)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 for remediation evidence create, got %d", createRecorder.Code)
	}

	listRecorder := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/remediations/remediation-1/evidence", nil)
	listRequest.Header.Set("Authorization", "Bearer appsec-token")

	server.httpServer.Handler.ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for remediation evidence list, got %d", listRecorder.Code)
	}
}

func TestOIDCStartRedirectsToProvider(t *testing.T) {
	t.Parallel()

	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": provider.URL + "/authorize",
				"token_endpoint":         provider.URL + "/token",
				"userinfo_endpoint":      provider.URL + "/userinfo",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	cfg := config.Load()
	cfg.OIDCIssuerURL = provider.URL
	cfg.OIDCClientID = "uss-client"
	cfg.OIDCClientSecret = "secret"
	cfg.OIDCRedirectURL = "http://127.0.0.1:18083/auth/oidc/callback"

	server := New(cfg, &stubAPIStore{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/oidc/start", nil)

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", recorder.Code)
	}

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if location.Path != "/authorize" {
		t.Fatalf("unexpected redirect path: %s", location.Path)
	}
	if location.Query().Get("client_id") != "uss-client" {
		t.Fatalf("unexpected client_id: %s", location.Query().Get("client_id"))
	}
	if location.Query().Get("code_challenge") == "" {
		t.Fatal("expected pkce challenge in redirect url")
	}

	cookies := recorder.Result().Cookies()
	if len(cookies) < 2 {
		t.Fatalf("expected oidc cookies to be set, got %d", len(cookies))
	}
}

func TestOIDCCallbackCreatesSessionCookie(t *testing.T) {
	t.Parallel()

	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": provider.URL + "/authorize",
				"token_endpoint":         provider.URL + "/token",
				"userinfo_endpoint":      provider.URL + "/userinfo",
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if r.Form.Get("code_verifier") != "verifier-value" {
				t.Fatalf("unexpected code verifier: %s", r.Form.Get("code_verifier"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "provider-access-token",
				"token_type":   "Bearer",
			})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer provider-access-token" {
				t.Fatalf("unexpected authorization header: %s", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sub":   "provider-user-1",
				"email": "oidc-user@example.com",
				"name":  "OIDC User",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	store := &stubAPIStore{
		createdOIDC: models.CreatedAPIToken{
			Token: models.APIToken{
				ID:        "token-oidc-1",
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			},
			PlaintextToken: "uss_oidc_session_token",
		},
	}

	cfg := config.Load()
	cfg.OIDCIssuerURL = provider.URL
	cfg.OIDCClientID = "uss-client"
	cfg.OIDCClientSecret = "secret"
	cfg.OIDCRedirectURL = "http://127.0.0.1:18083/auth/oidc/callback"

	server := New(cfg, store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=test-code&state=test-state", nil)
	request.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "test-state"})
	request.AddCookie(&http.Cookie{Name: oidcVerifierCookieName, Value: "verifier-value"})

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", recorder.Code)
	}
	if recorder.Header().Get("Location") != "/app/" {
		t.Fatalf("unexpected redirect location: %s", recorder.Header().Get("Location"))
	}
	if store.oidcEmail != "oidc-user@example.com" {
		t.Fatalf("unexpected oidc email: %s", store.oidcEmail)
	}
	if store.oidcSubject != "provider-user-1" {
		t.Fatalf("unexpected oidc subject: %s", store.oidcSubject)
	}

	foundSessionCookie := false
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value == "uss_oidc_session_token" {
			foundSessionCookie = true
			break
		}
	}
	if !foundSessionCookie {
		t.Fatal("expected session cookie to be set")
	}
}

func TestRootRedirectsToUIDistWhenConfigured(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "index.html"), []byte("<html>ui</html>"), 0o600); err != nil {
		t.Fatalf("write index html: %v", err)
	}

	cfg := config.Load()
	cfg.UIDistPath = tempDir

	server := New(cfg, &stubAPIStore{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", recorder.Code)
	}
	if recorder.Header().Get("Location") != "/ui/" {
		t.Fatalf("expected redirect to /ui/, got %s", recorder.Header().Get("Location"))
	}
}

func TestUIDistServesAssetsAndIndexFallback(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "index.html"), []byte("<html>ui</html>"), 0o600); err != nil {
		t.Fatalf("write index html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "app.js"), []byte("console.log('ui');"), 0o600); err != nil {
		t.Fatalf("write app js: %v", err)
	}

	cfg := config.Load()
	cfg.UIDistPath = tempDir

	server := New(cfg, &stubAPIStore{})

	for _, path := range []string{"/ui/", "/ui/app.js", "/ui/findings"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		server.httpServer.Handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d", path, recorder.Code)
		}
	}
}
