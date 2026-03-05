package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
	"unifiedsecurityscanner/control-plane/internal/rbac"
	"unifiedsecurityscanner/control-plane/internal/tenant"
)

//go:embed static/*
var staticAssets embed.FS

type Server struct {
	cfg        config.Config
	httpServer *http.Server
	store      apiStore
}

type apiStore interface {
	Ping(ctx context.Context) error
	AuthenticateToken(ctx context.Context, rawToken string) (models.AuthPrincipal, bool, error)
	CreateOIDCSession(ctx context.Context, provider string, subject string, email string, displayName string) (models.CreatedAPIToken, error)
	RecordAuditEvent(ctx context.Context, event models.AuditEvent) error
	ListAuditEvents(ctx context.Context, organizationID string, limit int) ([]models.AuditEvent, error)
	ListAPITokens(ctx context.Context, organizationID string, limit int) ([]models.APIToken, error)
	CreateAPIToken(ctx context.Context, principal models.AuthPrincipal, request models.CreateAPITokenRequest) (models.CreatedAPIToken, error)
	DisableAPIToken(ctx context.Context, organizationID string, tokenID string) (models.APIToken, bool, error)
	ListForTenant(ctx context.Context, tenantID string, limit int) ([]models.ScanJob, error)
	CreateForTenant(ctx context.Context, tenantID string, request models.CreateScanJobRequest) (models.ScanJob, error)
	GetForTenant(ctx context.Context, tenantID string, id string) (models.ScanJob, bool, error)
	RegisterWorker(ctx context.Context, request models.WorkerRegistrationRequest) (models.WorkerRegistrationResponse, error)
	RecordHeartbeat(ctx context.Context, request models.HeartbeatRequest) (models.HeartbeatResponse, error)
	ListFindingsForTenant(ctx context.Context, tenantID string, limit int) ([]models.CanonicalFinding, error)
	ListFindingWaiversForTenant(ctx context.Context, tenantID string, findingID string, limit int) ([]models.FindingWaiver, error)
	CreateFindingWaiverForTenant(ctx context.Context, tenantID string, findingID string, request models.CreateFindingWaiverRequest) (models.FindingWaiver, error)
	ListRiskSummaryForTenant(ctx context.Context, tenantID string) (models.RiskSummary, error)
	ListAssetsForTenant(ctx context.Context, tenantID string, limit int) ([]models.AssetSummary, error)
	GetAssetProfileForTenant(ctx context.Context, tenantID string, assetID string) (models.AssetProfile, bool, error)
	UpsertAssetProfileForTenant(ctx context.Context, tenantID string, assetID string, request models.UpsertAssetProfileRequest) (models.AssetProfile, error)
	SyncAssetProfilesForTenant(ctx context.Context, tenantID string, request models.SyncAssetProfilesRequest) (models.SyncAssetProfilesResult, error)
	ListCompensatingControlsForTenant(ctx context.Context, tenantID string, assetID string, limit int) ([]models.CompensatingControl, error)
	CreateCompensatingControlForTenant(ctx context.Context, tenantID string, assetID string, request models.CreateCompensatingControlRequest) (models.CompensatingControl, error)
	ListPoliciesForTenant(ctx context.Context, tenantID string, limit int) ([]models.Policy, error)
	GetPolicyForTenant(ctx context.Context, tenantID string, policyID string) (models.Policy, bool, error)
	CreatePolicyForTenant(ctx context.Context, tenantID string, request models.CreatePolicyRequest) (models.Policy, error)
	UpdatePolicyForTenant(ctx context.Context, tenantID string, policyID string, request models.UpdatePolicyRequest) (models.Policy, bool, error)
	ListPolicyVersionsForTenant(ctx context.Context, tenantID string, policyID string, limit int) ([]models.PolicyVersion, error)
	RollbackPolicyForTenant(ctx context.Context, tenantID string, policyID string, versionNumber int64, updatedBy string) (models.Policy, bool, error)
	ListPolicyApprovalsForTenant(ctx context.Context, tenantID string, limit int) ([]models.PolicyApproval, error)
	DecidePolicyApproval(ctx context.Context, tenantID string, approvalID string, approved bool, decidedBy string, reason string) (models.PolicyApproval, bool, error)
	ListRemediationsForTenant(ctx context.Context, tenantID string, limit int) ([]models.RemediationAction, error)
	GetRemediationForTenant(ctx context.Context, tenantID string, remediationID string) (models.RemediationAction, bool, error)
	CreateRemediationForTenant(ctx context.Context, tenantID string, request models.CreateRemediationRequest) (models.RemediationAction, error)
	TransitionRemediationForTenant(ctx context.Context, tenantID string, remediationID string, request models.TransitionRemediationRequest) (models.RemediationAction, bool, error)
	ListRemediationActivityForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationActivity, error)
	CreateRemediationCommentForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.CreateRemediationCommentRequest) (models.RemediationActivity, error)
	ListRemediationEvidenceForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationEvidence, error)
	CreateRemediationEvidenceForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.CreateRemediationEvidenceRequest) (models.RemediationEvidence, error)
	ListRemediationVerificationsForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationVerification, error)
	RequestRemediationRetestForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.CreateRetestRequest) (models.RemediationVerification, models.ScanJob, error)
	RecordRemediationVerificationForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.RecordRemediationVerificationRequest) (models.RemediationVerification, bool, error)
	ListRemediationExceptionsForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationException, error)
	CreateRemediationExceptionForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.CreateRemediationExceptionRequest) (models.RemediationException, error)
	DecideRemediationExceptionForTenant(ctx context.Context, tenantID string, exceptionID string, approved bool, actor string, reason string) (models.RemediationException, bool, error)
	ListRemediationTicketLinksForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationTicketLink, error)
	CreateRemediationTicketLinkForTenant(ctx context.Context, tenantID string, remediationID string, request models.CreateRemediationTicketLinkRequest) (models.RemediationTicketLink, error)
	SyncRemediationTicketLinkForTenant(ctx context.Context, tenantID string, remediationID string, ticketID string, request models.SyncRemediationTicketLinkRequest) (models.RemediationTicketLink, bool, error)
	ListRemediationAssignmentRequestsForTenant(ctx context.Context, tenantID string, remediationID string, limit int) ([]models.RemediationAssignmentRequest, error)
	CreateRemediationAssignmentRequestForTenant(ctx context.Context, tenantID string, remediationID string, actor string, request models.CreateRemediationAssignmentRequest) (models.RemediationAssignmentRequest, error)
	DecideRemediationAssignmentRequestForTenant(ctx context.Context, tenantID string, requestID string, approved bool, actor string, reason string) (models.RemediationAssignmentRequest, bool, error)
	ListNotificationEventsForTenant(ctx context.Context, tenantID string, limit int) ([]models.NotificationEvent, error)
	AcknowledgeNotificationEventForTenant(ctx context.Context, tenantID string, notificationID string, actor string) (models.NotificationEvent, bool, error)
	SweepRemediationEscalationsForTenant(ctx context.Context, tenantID string, actor string) (models.NotificationSweepResult, error)
}

func New(cfg config.Config, store apiStore) *Server {
	server := &Server{
		cfg:   cfg,
		store: store,
	}

	webFS, err := fs.Sub(staticAssets, "static")
	if err != nil {
		panic("embedded web ui assets are missing")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.handleHealth)
	mux.HandleFunc("/readyz", server.handleReady)
	mux.HandleFunc("/auth/oidc/start", server.handleOIDCStart)
	mux.HandleFunc("/auth/oidc/callback", server.handleOIDCCallback)
	mux.HandleFunc("/auth/logout", server.handleLogout)
	mux.HandleFunc("/v1/meta", server.withUserAuth(auth.PermissionMetaRead, "meta.read", "service", server.handleMeta))
	mux.HandleFunc("/v1/auth/me", server.withUserAuth(auth.PermissionSessionRead, "session.read", "session", server.handleSession))
	mux.HandleFunc("/v1/auth/tokens", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionTokensRead,
		http.MethodPost: auth.PermissionTokensWrite,
	}, "auth_tokens", "api_token", server.handleAuthTokens))
	mux.HandleFunc("/v1/auth/tokens/", server.withUserAuth(auth.PermissionTokensWrite, "auth_token.disable", "api_token", server.handleAuthTokenByID))
	mux.HandleFunc("/v1/audit-events", server.withUserAuth(auth.PermissionAuditRead, "audit.list", "audit_event", server.handleAuditEvents))
	mux.HandleFunc("/v1/scan-jobs", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionScanJobsRead,
		http.MethodPost: auth.PermissionScanJobsWrite,
	}, "scan_jobs", "scan_job", server.handleScanJobs))
	mux.HandleFunc("/v1/scan-jobs/", server.withUserAuth(auth.PermissionScanJobsRead, "scan_job.read", "scan_job", server.handleScanJobByID))
	mux.HandleFunc("/v1/findings", server.withUserAuth(auth.PermissionFindingsRead, "findings.list", "finding", server.handleFindings))
	mux.HandleFunc("/v1/findings/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionFindingsRead,
		http.MethodPost: auth.PermissionRemediationsWrite,
	}, "finding", "finding", server.handleFindingRoute))
	mux.HandleFunc("/v1/risk/summary", server.withUserAuth(auth.PermissionFindingsRead, "risk.summary", "risk_summary", server.handleRiskSummary))
	mux.HandleFunc("/v1/assets", server.withUserAuth(auth.PermissionAssetsRead, "assets.list", "asset", server.handleAssets))
	mux.HandleFunc("/v1/assets/sync", server.withUserAuth(auth.PermissionAssetsWrite, "assets.sync", "asset", server.handleAssetSync))
	mux.HandleFunc("/v1/assets/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionAssetsRead,
		http.MethodPut:  auth.PermissionAssetsWrite,
		http.MethodPost: auth.PermissionAssetsWrite,
	}, "asset", "asset", server.handleAssetRoute))
	mux.HandleFunc("/v1/policies", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "policies", "policy", server.handlePolicies))
	mux.HandleFunc("/v1/policies/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionPoliciesRead,
		http.MethodPut:  auth.PermissionPoliciesWrite,
		http.MethodPost: auth.PermissionPoliciesWrite,
	}, "policy", "policy", server.handlePolicyRoute))
	mux.HandleFunc("/v1/policy-approvals", server.withUserAuth(auth.PermissionPoliciesRead, "policy_approvals.list", "policy_approval", server.handlePolicyApprovals))
	mux.HandleFunc("/v1/policy-approvals/", server.withUserAuth(auth.PermissionPoliciesWrite, "policy_approval.decide", "policy_approval", server.handlePolicyApprovalDecision))
	mux.HandleFunc("/v1/remediations", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionRemediationsRead,
		http.MethodPost: auth.PermissionRemediationsWrite,
	}, "remediations", "remediation", server.handleRemediations))
	mux.HandleFunc("/v1/remediations/", server.withUserAuthForMethod(map[string]auth.Permission{
		http.MethodGet:  auth.PermissionRemediationsRead,
		http.MethodPost: auth.PermissionRemediationsWrite,
	}, "remediation", "remediation", server.handleRemediationRoute))
	mux.HandleFunc("/v1/remediation-exceptions/", server.withUserAuth(auth.PermissionRemediationsWrite, "remediation_exception.decide", "remediation_exception", server.handleRemediationExceptionDecision))
	mux.HandleFunc("/v1/remediation-assignments/", server.withUserAuth(auth.PermissionRemediationsWrite, "remediation_assignment.decide", "remediation_assignment", server.handleRemediationAssignmentDecision))
	mux.HandleFunc("/v1/notifications", server.withUserAuth(auth.PermissionRemediationsRead, "notifications.list", "notification", server.handleNotifications))
	mux.HandleFunc("/v1/notifications/", server.withUserAuth(auth.PermissionRemediationsWrite, "notification.ack", "notification", server.handleNotificationRoute))
	mux.HandleFunc("/v1/remediation-escalations/sweep", server.withUserAuth(auth.PermissionRemediationsWrite, "remediation_escalations.sweep", "notification", server.handleRemediationEscalationSweep))
	mux.HandleFunc("/v1/workers/register", server.withWorkerAuth(server.handleWorkerRegister))
	mux.HandleFunc("/v1/workers/heartbeat", server.withWorkerAuth(server.handleWorkerHeartbeat))
	mux.HandleFunc("/app", server.handleAppRoot)
	mux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.FS(webFS))))
	mux.HandleFunc("/", server.handleRoot)

	server.httpServer = &http.Server{
		Addr:              cfg.APIBindAddress,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return server
}

func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "control-plane-api",
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	if err := s.store.Ping(r.Context()); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "database_unavailable", "database is not reachable")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ready",
		"service": "control-plane-api",
	})
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	s.writeJSON(w, http.StatusOK, models.ServiceMetadata{
		Name:                      "unified-security-scanner-control-plane",
		Version:                   s.cfg.BuildVersion,
		SchedulerIntervalSeconds:  int64(s.cfg.SchedulerInterval.Seconds()),
		WorkerHeartbeatTTLSeconds: int64(s.cfg.WorkerHeartbeatTTL.Seconds()),
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	s.writeJSON(w, http.StatusOK, models.AuthSession{
		Principal:      principal,
		SSOEnabled:     s.oidcConfigured(),
		OIDCIssuerURL:  s.cfg.OIDCIssuerURL,
		OIDCClientID:   s.cfg.OIDCClientID,
		BootstrapToken: auth.IsBootstrapToken(principal),
	})
}

func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	events, err := s.store.ListAuditEvents(r.Context(), principal.OrganizationID, 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_audit_events_failed", "audit events could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": events,
	})
}

func (s *Server) handleAuthTokens(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		tokens, err := s.store.ListAPITokens(r.Context(), principal.OrganizationID, 200)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_api_tokens_failed", "api tokens could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": tokens,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateAPITokenRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		if strings.TrimSpace(request.TokenName) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "token_name is required")
			return
		}
		if request.ExpiresAt != nil && !request.ExpiresAt.After(time.Now().UTC()) {
			s.writeError(w, http.StatusBadRequest, "validation_error", "expires_at must be in the future")
			return
		}

		createdToken, err := s.store.CreateAPIToken(r.Context(), principal, request)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidScope) {
				s.writeError(w, http.StatusBadRequest, "invalid_scope", "the requested token scopes are not allowed for the current role")
				return
			}

			s.writeError(w, http.StatusInternalServerError, "create_api_token_failed", "api token could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, createdToken)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleAuthTokenByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/auth/tokens/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "disable" {
		s.writeError(w, http.StatusNotFound, "auth_token_route_not_found", "the requested api token route was not found")
		return
	}

	token, found, err := s.store.DisableAPIToken(r.Context(), principal.OrganizationID, parts[0])
	if err != nil {
		if errors.Is(err, jobs.ErrProtectedToken) {
			s.writeError(w, http.StatusConflict, "protected_api_token", "the bootstrap token cannot be disabled while it is the only guaranteed access path")
			return
		}

		s.writeError(w, http.StatusInternalServerError, "disable_api_token_failed", "api token could not be disabled")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "api_token_not_found", "api token was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, token)
}

func (s *Server) handleScanJobs(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		jobsList, err := s.store.ListForTenant(r.Context(), principal.OrganizationID, 100)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_scan_jobs_failed", "scan jobs could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": jobsList,
		})
	case http.MethodPost:
		s.createScanJob(w, r, principal)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleScanJobByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	jobID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/scan-jobs/"))
	if jobID == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_job_id", "scan job id is required")
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	job, found, err := s.store.GetForTenant(r.Context(), principal.OrganizationID, jobID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "get_scan_job_failed", "scan job could not be loaded")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "scan_job_not_found", "scan job was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleWorkerRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	defer r.Body.Close()

	var request models.WorkerRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	if strings.TrimSpace(request.WorkerID) == "" ||
		strings.TrimSpace(request.WorkerVersion) == "" ||
		strings.TrimSpace(request.OperatingSystem) == "" ||
		strings.TrimSpace(request.Hostname) == "" {
		s.writeError(w, http.StatusBadRequest, "validation_error", "worker_id, worker_version, operating_system, and hostname are required")
		return
	}

	response, err := s.store.RegisterWorker(r.Context(), request)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "register_worker_failed", "worker could not be registered")
		return
	}

	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleWorkerHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	defer r.Body.Close()

	var request models.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	if strings.TrimSpace(request.WorkerID) == "" || strings.TrimSpace(request.LeaseID) == "" {
		s.writeError(w, http.StatusBadRequest, "validation_error", "worker_id and lease_id are required")
		return
	}

	response, err := s.store.RecordHeartbeat(r.Context(), request)
	if err != nil {
		if errors.Is(err, jobs.ErrWorkerLeaseNotFound) {
			s.writeError(w, http.StatusNotFound, "worker_lease_not_found", "worker registration lease was not found")
			return
		}

		s.writeError(w, http.StatusInternalServerError, "heartbeat_failed", "worker heartbeat could not be recorded")
		return
	}

	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	findings, err := s.store.ListFindingsForTenant(r.Context(), principal.OrganizationID, 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_findings_failed", "findings could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": findings,
	})
}

func (s *Server) handleFindingRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/findings/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "waivers" {
		s.writeError(w, http.StatusNotFound, "finding_route_not_found", "the requested finding route was not found")
		return
	}

	findingID := strings.TrimSpace(parts[0])
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListFindingWaiversForTenant(r.Context(), principal.OrganizationID, findingID, 200)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_finding_waivers_failed", "finding waivers could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateFindingWaiverRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.RemediationID) == "" || strings.TrimSpace(request.Reason) == "" || request.Reduction <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "remediation_id, reason, and a positive reduction are required")
			return
		}
		if request.ExpiresAt != nil && !request.ExpiresAt.After(time.Now().UTC()) {
			s.writeError(w, http.StatusBadRequest, "validation_error", "expires_at must be in the future")
			return
		}

		waiver, err := s.store.CreateFindingWaiverForTenant(r.Context(), principal.OrganizationID, findingID, request)
		if err != nil {
			if errors.Is(err, jobs.ErrInvalidWaiver) {
				s.writeError(w, http.StatusConflict, "invalid_finding_waiver", "the waiver dependencies are not valid for this finding")
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_finding_waiver_failed", "finding waiver could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, waiver)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleRiskSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	summary, err := s.store.ListRiskSummaryForTenant(r.Context(), principal.OrganizationID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "risk_summary_failed", "risk summary could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	assets, err := s.store.ListAssetsForTenant(r.Context(), principal.OrganizationID, 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_assets_failed", "assets could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": assets,
	})
}

func (s *Server) handleAssetSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	defer r.Body.Close()

	var request models.SyncAssetProfilesRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	if len(request.Assets) == 0 {
		s.writeError(w, http.StatusBadRequest, "validation_error", "assets must contain at least one item")
		return
	}

	result, err := s.store.SyncAssetProfilesForTenant(r.Context(), principal.OrganizationID, request)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "asset_sync_failed", "asset profiles could not be synchronized")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAssetRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/assets/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "asset_route_not_found", "the requested asset route was not found")
		return
	}

	assetID, err := url.PathUnescape(strings.TrimSpace(parts[0]))
	if err != nil || strings.TrimSpace(assetID) == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_asset_id", "asset id is invalid")
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			profile, found, err := s.store.GetAssetProfileForTenant(r.Context(), principal.OrganizationID, assetID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_asset_profile_failed", "asset profile could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "asset_profile_not_found", "asset profile was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, profile)
			return
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpsertAssetProfileRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.AssetType) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "asset_type is required")
				return
			}

			profile, err := s.store.UpsertAssetProfileForTenant(r.Context(), principal.OrganizationID, assetID, request)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "upsert_asset_profile_failed", "asset profile could not be saved")
				return
			}

			s.writeJSON(w, http.StatusOK, profile)
			return
		default:
			s.writeMethodNotAllowed(w)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "controls" {
		switch r.Method {
		case http.MethodGet:
			controls, err := s.store.ListCompensatingControlsForTenant(r.Context(), principal.OrganizationID, assetID, 200)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "list_compensating_controls_failed", "compensating controls could not be loaded")
				return
			}
			s.writeJSON(w, http.StatusOK, map[string]any{
				"items": controls,
			})
			return
		case http.MethodPost:
			defer r.Body.Close()

			var request models.CreateCompensatingControlRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.Name) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "name is required")
				return
			}

			control, err := s.store.CreateCompensatingControlForTenant(r.Context(), principal.OrganizationID, assetID, request)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "create_compensating_control_failed", "compensating control could not be created")
				return
			}

			s.writeJSON(w, http.StatusCreated, control)
			return
		default:
			s.writeMethodNotAllowed(w)
			return
		}
	}

	s.writeError(w, http.StatusNotFound, "asset_route_not_found", "the requested asset route was not found")
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		policies, err := s.store.ListPoliciesForTenant(r.Context(), principal.OrganizationID, 200)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_policies_failed", "policies could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": policies,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreatePolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		if strings.TrimSpace(request.Name) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "name is required")
			return
		}

		request.UpdatedBy = principal.Email
		tenantID := principal.OrganizationID
		if request.Global {
			if principal.Role != auth.RolePlatformAdmin {
				s.writeError(w, http.StatusForbidden, "permission_denied", "only platform administrators can create global policies")
				return
			}
			tenantID = ""
			if strings.TrimSpace(request.Scope) == "" {
				request.Scope = "global"
			}
		}

		policy, err := s.store.CreatePolicyForTenant(r.Context(), tenantID, request)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "create_policy_failed", "policy could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, policy)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handlePolicyRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/policies/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "policy_route_not_found", "the requested policy route was not found")
		return
	}

	policyID := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			policy, found, err := s.store.GetPolicyForTenant(r.Context(), principal.OrganizationID, policyID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_policy_failed", "policy could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "policy_not_found", "policy was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, policy)
			return
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpdatePolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.Name) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "name is required")
				return
			}

			request.UpdatedBy = principal.Email
			targetTenantID := principal.OrganizationID
			current, found, err := s.store.GetPolicyForTenant(r.Context(), principal.OrganizationID, policyID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_policy_failed", "policy could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "policy_not_found", "policy was not found")
				return
			}
			if current.TenantID == "" {
				if principal.Role != auth.RolePlatformAdmin {
					s.writeError(w, http.StatusForbidden, "permission_denied", "only platform administrators can modify global policies")
					return
				}
				targetTenantID = ""
			}

			updated, found, err := s.store.UpdatePolicyForTenant(r.Context(), targetTenantID, policyID, request)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "update_policy_failed", "policy could not be updated")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "policy_not_found", "policy was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, updated)
			return
		default:
			s.writeMethodNotAllowed(w)
			return
		}
	}

	if len(parts) == 2 && parts[1] == "versions" && r.Method == http.MethodGet {
		versions, err := s.store.ListPolicyVersionsForTenant(r.Context(), principal.OrganizationID, policyID, 200)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_policy_versions_failed", "policy versions could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": versions,
		})
		return
	}

	if len(parts) == 2 && parts[1] == "rollback" && r.Method == http.MethodPost {
		defer r.Body.Close()

		var request models.PolicyRollbackRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if request.VersionNumber <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "version_number must be greater than zero")
			return
		}

		targetTenantID := principal.OrganizationID
		current, found, err := s.store.GetPolicyForTenant(r.Context(), principal.OrganizationID, policyID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_policy_failed", "policy could not be loaded")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "policy_not_found", "policy was not found")
			return
		}
		if current.TenantID == "" {
			if principal.Role != auth.RolePlatformAdmin {
				s.writeError(w, http.StatusForbidden, "permission_denied", "only platform administrators can rollback global policies")
				return
			}
			targetTenantID = ""
		}

		rolledBack, found, err := s.store.RollbackPolicyForTenant(r.Context(), targetTenantID, policyID, request.VersionNumber, principal.Email)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "rollback_policy_failed", "policy could not be rolled back")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "policy_version_not_found", "policy version was not found")
			return
		}

		s.writeJSON(w, http.StatusOK, rolledBack)
		return
	}

	s.writeError(w, http.StatusNotFound, "policy_route_not_found", "the requested policy route was not found")
}

func (s *Server) handlePolicyApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	items, err := s.store.ListPolicyApprovalsForTenant(r.Context(), principal.OrganizationID, 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_policy_approvals_failed", "policy approvals could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
	})
}

func (s *Server) handlePolicyApprovalDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/policy-approvals/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "policy_approval_route_not_found", "the requested policy approval route was not found")
		return
	}

	approved := false
	switch parts[1] {
	case "approve":
		approved = true
	case "deny":
		approved = false
	default:
		s.writeError(w, http.StatusNotFound, "policy_approval_route_not_found", "the requested policy approval route was not found")
		return
	}

	defer r.Body.Close()

	var request models.PolicyApprovalDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	item, found, err := s.store.DecidePolicyApproval(r.Context(), principal.OrganizationID, parts[0], approved, principal.Email, request.Reason)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "policy_approval_decision_failed", "policy approval could not be updated")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "policy_approval_not_found", "policy approval was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleRemediations(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListRemediationsForTenant(r.Context(), principal.OrganizationID, 200)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_remediations_failed", "remediation actions could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateRemediationRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		if strings.TrimSpace(request.FindingID) == "" || strings.TrimSpace(request.Title) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "finding_id and title are required")
			return
		}

		item, err := s.store.CreateRemediationForTenant(r.Context(), principal.OrganizationID, request)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "create_remediation_failed", "remediation action could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleRemediationRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediations/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "remediation_route_not_found", "the requested remediation route was not found")
		return
	}

	remediationID := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			s.writeMethodNotAllowed(w)
			return
		}

		item, found, err := s.store.GetRemediationForTenant(r.Context(), principal.OrganizationID, remediationID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_remediation_failed", "remediation action could not be loaded")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
			return
		}

		s.writeJSON(w, http.StatusOK, item)
		return
	}

	if len(parts) == 2 {
		switch parts[1] {
		case "transition":
			if r.Method != http.MethodPost {
				s.writeMethodNotAllowed(w)
				return
			}

			defer r.Body.Close()

			var request models.TransitionRemediationRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.Status) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "status is required")
				return
			}

			item, found, err := s.store.TransitionRemediationForTenant(r.Context(), principal.OrganizationID, remediationID, request)
			if err != nil {
				if errors.Is(err, jobs.ErrInvalidRemediationTransition) {
					s.writeError(w, http.StatusConflict, "invalid_remediation_transition", "the requested remediation transition is not allowed")
					return
				}
				s.writeError(w, http.StatusInternalServerError, "transition_remediation_failed", "remediation action could not be transitioned")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
				return
			}

			s.writeJSON(w, http.StatusOK, item)
			return
		case "activity":
			if r.Method != http.MethodGet {
				s.writeMethodNotAllowed(w)
				return
			}

			items, err := s.store.ListRemediationActivityForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "list_remediation_activity_failed", "remediation activity could not be loaded")
				return
			}

			s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			return
		case "comments":
			if r.Method != http.MethodPost {
				s.writeMethodNotAllowed(w)
				return
			}
			defer r.Body.Close()

			var request models.CreateRemediationCommentRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.Comment) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "comment is required")
				return
			}

			item, err := s.store.CreateRemediationCommentForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
			if err != nil {
				if errors.Is(err, jobs.ErrTaskNotFound) {
					s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
					return
				}
				s.writeError(w, http.StatusInternalServerError, "create_remediation_comment_failed", "remediation comment could not be created")
				return
			}

			s.writeJSON(w, http.StatusCreated, item)
			return
		case "evidence":
			switch r.Method {
			case http.MethodGet:
				items, err := s.store.ListRemediationEvidenceForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
				if err != nil {
					s.writeError(w, http.StatusInternalServerError, "list_remediation_evidence_failed", "remediation evidence could not be loaded")
					return
				}
				s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			case http.MethodPost:
				defer r.Body.Close()

				var request models.CreateRemediationEvidenceRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
					return
				}
				if strings.TrimSpace(request.Kind) == "" || strings.TrimSpace(request.Ref) == "" {
					s.writeError(w, http.StatusBadRequest, "validation_error", "kind and ref are required")
					return
				}

				item, err := s.store.CreateRemediationEvidenceForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
				if err != nil {
					if errors.Is(err, jobs.ErrTaskNotFound) {
						s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
						return
					}
					s.writeError(w, http.StatusInternalServerError, "create_remediation_evidence_failed", "remediation evidence could not be created")
					return
				}
				s.writeJSON(w, http.StatusCreated, item)
			default:
				s.writeMethodNotAllowed(w)
			}
			return
		case "verifications":
			if r.Method != http.MethodGet {
				s.writeMethodNotAllowed(w)
				return
			}

			items, err := s.store.ListRemediationVerificationsForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "list_remediation_verifications_failed", "remediation verifications could not be loaded")
				return
			}

			s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			return
		case "retest":
			if r.Method != http.MethodPost {
				s.writeMethodNotAllowed(w)
				return
			}
			defer r.Body.Close()

			var request models.CreateRetestRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			verification, job, err := s.store.RequestRemediationRetestForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
			if err != nil {
				switch {
				case errors.Is(err, jobs.ErrTaskNotFound):
					s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
				case errors.Is(err, jobs.ErrInvalidVerification), errors.Is(err, jobs.ErrInvalidRemediationTransition):
					s.writeError(w, http.StatusConflict, "invalid_retest_request", "the remediation is not in a state that allows retest")
				default:
					s.writeError(w, http.StatusInternalServerError, "request_retest_failed", "retest could not be requested")
				}
				return
			}

			s.writeJSON(w, http.StatusCreated, map[string]any{
				"verification": verification,
				"scan_job":     job,
			})
			return
		case "verify":
			if r.Method != http.MethodPost {
				s.writeMethodNotAllowed(w)
				return
			}
			defer r.Body.Close()

			var request models.RecordRemediationVerificationRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.VerificationID) == "" || strings.TrimSpace(request.Outcome) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "verification_id and outcome are required")
				return
			}

			item, found, err := s.store.RecordRemediationVerificationForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
			if err != nil {
				if errors.Is(err, jobs.ErrInvalidVerification) {
					s.writeError(w, http.StatusConflict, "invalid_remediation_verification", "the remediation verification could not be completed")
					return
				}
				s.writeError(w, http.StatusInternalServerError, "complete_remediation_verification_failed", "remediation verification could not be completed")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "remediation_verification_not_found", "remediation verification was not found")
				return
			}

			s.writeJSON(w, http.StatusOK, item)
			return
		case "exceptions":
			switch r.Method {
			case http.MethodGet:
				items, err := s.store.ListRemediationExceptionsForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
				if err != nil {
					s.writeError(w, http.StatusInternalServerError, "list_remediation_exceptions_failed", "remediation exceptions could not be loaded")
					return
				}
				s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			case http.MethodPost:
				defer r.Body.Close()

				var request models.CreateRemediationExceptionRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
					return
				}
				if strings.TrimSpace(request.Reason) == "" || request.Reduction <= 0 {
					s.writeError(w, http.StatusBadRequest, "validation_error", "reason and a positive reduction are required")
					return
				}

				item, err := s.store.CreateRemediationExceptionForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
				if err != nil {
					switch {
					case errors.Is(err, jobs.ErrTaskNotFound):
						s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
					case errors.Is(err, jobs.ErrInvalidExceptionDecision):
						s.writeError(w, http.StatusConflict, "invalid_remediation_exception", "the remediation exception is not valid")
					default:
						s.writeError(w, http.StatusInternalServerError, "create_remediation_exception_failed", "remediation exception could not be created")
					}
					return
				}
				s.writeJSON(w, http.StatusCreated, item)
			default:
				s.writeMethodNotAllowed(w)
			}
			return
		case "tickets":
			switch r.Method {
			case http.MethodGet:
				items, err := s.store.ListRemediationTicketLinksForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
				if err != nil {
					s.writeError(w, http.StatusInternalServerError, "list_remediation_tickets_failed", "remediation tickets could not be loaded")
					return
				}
				s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			case http.MethodPost:
				defer r.Body.Close()

				var request models.CreateRemediationTicketLinkRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
					return
				}
				if strings.TrimSpace(request.Provider) == "" || strings.TrimSpace(request.ExternalID) == "" {
					s.writeError(w, http.StatusBadRequest, "validation_error", "provider and external_id are required")
					return
				}

				item, err := s.store.CreateRemediationTicketLinkForTenant(r.Context(), principal.OrganizationID, remediationID, request)
				if err != nil {
					switch {
					case errors.Is(err, jobs.ErrTaskNotFound):
						s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
					case errors.Is(err, jobs.ErrInvalidExceptionDecision):
						s.writeError(w, http.StatusConflict, "invalid_remediation_ticket", "the remediation ticket link is not valid")
					default:
						s.writeError(w, http.StatusInternalServerError, "create_remediation_ticket_failed", "remediation ticket could not be created")
					}
					return
				}
				s.writeJSON(w, http.StatusCreated, item)
			default:
				s.writeMethodNotAllowed(w)
			}
			return
		case "assignment-requests":
			switch r.Method {
			case http.MethodGet:
				items, err := s.store.ListRemediationAssignmentRequestsForTenant(r.Context(), principal.OrganizationID, remediationID, 200)
				if err != nil {
					s.writeError(w, http.StatusInternalServerError, "list_remediation_assignment_requests_failed", "remediation assignment requests could not be loaded")
					return
				}
				s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
			case http.MethodPost:
				defer r.Body.Close()

				var request models.CreateRemediationAssignmentRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
					return
				}
				if strings.TrimSpace(request.RequestedOwner) == "" {
					s.writeError(w, http.StatusBadRequest, "validation_error", "requested_owner is required")
					return
				}

				item, err := s.store.CreateRemediationAssignmentRequestForTenant(r.Context(), principal.OrganizationID, remediationID, principal.Email, request)
				if err != nil {
					if errors.Is(err, jobs.ErrTaskNotFound) {
						s.writeError(w, http.StatusNotFound, "remediation_not_found", "remediation action was not found")
						return
					}
					s.writeError(w, http.StatusInternalServerError, "create_remediation_assignment_request_failed", "remediation assignment request could not be created")
					return
				}
				s.writeJSON(w, http.StatusCreated, item)
			default:
				s.writeMethodNotAllowed(w)
			}
			return
		}
	}

	if len(parts) == 4 && parts[1] == "tickets" && parts[3] == "sync" {
		if r.Method != http.MethodPost {
			s.writeMethodNotAllowed(w)
			return
		}
		if strings.TrimSpace(parts[2]) == "" {
			s.writeError(w, http.StatusNotFound, "remediation_route_not_found", "the requested remediation route was not found")
			return
		}

		defer r.Body.Close()

		var request models.SyncRemediationTicketLinkRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		item, found, err := s.store.SyncRemediationTicketLinkForTenant(r.Context(), principal.OrganizationID, remediationID, strings.TrimSpace(parts[2]), request)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "sync_remediation_ticket_failed", "remediation ticket could not be synchronized")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "remediation_ticket_not_found", "remediation ticket was not found")
			return
		}

		s.writeJSON(w, http.StatusOK, item)
		return
	}

	s.writeError(w, http.StatusNotFound, "remediation_route_not_found", "the requested remediation route was not found")
}

func (s *Server) handleRemediationExceptionDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediation-exceptions/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "remediation_exception_route_not_found", "the requested remediation exception route was not found")
		return
	}

	approved := false
	switch parts[1] {
	case "approve":
		approved = true
	case "deny":
		approved = false
	default:
		s.writeError(w, http.StatusNotFound, "remediation_exception_route_not_found", "the requested remediation exception route was not found")
		return
	}

	defer r.Body.Close()

	var request models.DecideRemediationExceptionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	item, found, err := s.store.DecideRemediationExceptionForTenant(r.Context(), principal.OrganizationID, parts[0], approved, principal.Email, request.Reason)
	if err != nil {
		if errors.Is(err, jobs.ErrInvalidExceptionDecision) {
			s.writeError(w, http.StatusConflict, "invalid_remediation_exception_decision", "the remediation exception could not be decided")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "decide_remediation_exception_failed", "remediation exception could not be updated")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "remediation_exception_not_found", "remediation exception was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleRemediationAssignmentDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediation-assignments/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "remediation_assignment_route_not_found", "the requested remediation assignment route was not found")
		return
	}

	approved := false
	switch parts[1] {
	case "approve":
		approved = true
	case "deny":
		approved = false
	default:
		s.writeError(w, http.StatusNotFound, "remediation_assignment_route_not_found", "the requested remediation assignment route was not found")
		return
	}

	defer r.Body.Close()

	var request models.DecideRemediationAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	item, found, err := s.store.DecideRemediationAssignmentRequestForTenant(r.Context(), principal.OrganizationID, parts[0], approved, principal.Email, request.Reason)
	if err != nil {
		if errors.Is(err, jobs.ErrInvalidAssignmentDecision) {
			s.writeError(w, http.StatusConflict, "invalid_remediation_assignment_decision", "the remediation assignment request could not be decided")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "decide_remediation_assignment_failed", "remediation assignment request could not be updated")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "remediation_assignment_not_found", "remediation assignment request was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	items, err := s.store.ListNotificationEventsForTenant(r.Context(), principal.OrganizationID, 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_notifications_failed", "notification events could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleNotificationRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/notifications/"))
	parts := strings.Split(path, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "ack" {
		s.writeError(w, http.StatusNotFound, "notification_route_not_found", "the requested notification route was not found")
		return
	}

	item, found, err := s.store.AcknowledgeNotificationEventForTenant(r.Context(), principal.OrganizationID, parts[0], principal.Email)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "acknowledge_notification_failed", "notification event could not be acknowledged")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "notification_not_found", "notification event was not found")
		return
	}

	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleRemediationEscalationSweep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	result, err := s.store.SweepRemediationEscalationsForTenant(r.Context(), principal.OrganizationID, principal.Email)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "sweep_remediation_escalations_failed", "remediation escalations could not be processed")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) createScanJob(w http.ResponseWriter, r *http.Request, principal models.AuthPrincipal) {
	defer r.Body.Close()

	var request models.CreateScanJobRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	if strings.TrimSpace(request.TargetKind) == "" ||
		strings.TrimSpace(request.Target) == "" ||
		strings.TrimSpace(request.Profile) == "" {
		s.writeError(w, http.StatusBadRequest, "validation_error", "target_kind, target, and profile are required")
		return
	}

	if request.TenantID != "" && strings.TrimSpace(request.TenantID) != principal.OrganizationID {
		s.writeError(w, http.StatusForbidden, "tenant_scope_violation", "scan jobs can only be created in the authenticated tenant")
		return
	}

	request.TenantID = principal.OrganizationID
	request.RequestedBy = principal.Email

	job, err := s.store.CreateForTenant(r.Context(), principal.OrganizationID, request)
	if err != nil {
		var denied *jobs.PolicyDeniedError
		if errors.As(err, &denied) {
			s.writeJSON(w, http.StatusForbidden, map[string]any{
				"code":      "policy_denied",
				"message":   denied.Error(),
				"policy_id": denied.PolicyID,
				"rule_hits": denied.RuleHits,
			})
			return
		}
		s.writeError(w, http.StatusInternalServerError, "create_scan_job_failed", "scan job could not be created")
		return
	}

	s.writeJSON(w, http.StatusCreated, job)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	http.Redirect(w, r, "/app/", http.StatusTemporaryRedirect)
}

func (s *Server) handleAppRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/app" {
		http.NotFound(w, r)
		return
	}

	http.Redirect(w, r, "/app/", http.StatusTemporaryRedirect)
}

func (s *Server) withUserAuth(permission auth.Permission, action string, resourceType string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.extractAuthToken(r)
		if token == "" {
			s.writeError(w, http.StatusUnauthorized, "authentication_required", "an api token or browser session is required")
			return
		}

		principal, ok, err := s.store.AuthenticateToken(r.Context(), token)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "authentication_failed", "authentication could not be completed")
			return
		}
		if !ok {
			s.writeError(w, http.StatusUnauthorized, "invalid_bearer_token", "the supplied bearer token is invalid")
			return
		}

		if err := tenant.RequirePrincipalOrganization(principal); err != nil {
			s.recordAuditEvent(r.Context(), principal, action, resourceType, "", "denied", r, map[string]any{
				"permission": string(permission),
				"reason":     "tenant",
			})
			s.writeError(w, http.StatusForbidden, "permission_denied", "the current identity is not allowed to perform this action")
			return
		}

		if err := rbac.Authorize(principal, permission); err != nil {
			reason := rbac.Reason(err)
			if reason == "" {
				reason = "authorization"
			}
			s.recordAuditEvent(r.Context(), principal, action, resourceType, "", "denied", r, map[string]any{
				"permission": string(permission),
				"reason":     reason,
			})
			s.writeError(w, http.StatusForbidden, "permission_denied", "the current identity is not allowed to perform this action")
			return
		}

		recorder := &auditedResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next(recorder, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
		s.recordAuditEvent(r.Context(), principal, action, resourceType, s.resourceIDFromRequest(r), http.StatusText(recorder.status), r, map[string]any{
			"permission":  string(permission),
			"status_code": recorder.status,
		})
	}
}

func (s *Server) withUserAuthForMethod(permissions map[string]auth.Permission, actionPrefix string, resourceType string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		permission, ok := permissions[r.Method]
		if !ok {
			s.writeMethodNotAllowed(w)
			return
		}

		action := actionPrefix + "." + strings.ToLower(r.Method)
		s.withUserAuth(permission, action, resourceType, next)(w, r)
	}
}

func (s *Server) withWorkerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.WorkerSharedSecret != "" && r.Header.Get(auth.WorkerSecretHeader) != s.cfg.WorkerSharedSecret {
			s.writeError(w, http.StatusUnauthorized, "invalid_worker_secret", "the worker secret is invalid")
			return
		}

		next(w, r)
	}
}

func (s *Server) recordAuditEvent(ctx context.Context, principal models.AuthPrincipal, action string, resourceType string, resourceID string, statusText string, r *http.Request, details map[string]any) {
	statusText = strings.ToLower(strings.TrimSpace(statusText))
	if statusText == "" {
		statusText = "unknown"
	}

	_ = s.store.RecordAuditEvent(ctx, models.AuditEvent{
		OrganizationID: principal.OrganizationID,
		ActorUserID:    principal.UserID,
		ActorEmail:     principal.Email,
		Action:         action,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		Status:         statusText,
		RequestMethod:  r.Method,
		RequestPath:    r.URL.Path,
		RemoteAddr:     r.RemoteAddr,
		Details:        details,
		CreatedAt:      time.Now().UTC(),
	})
}

func (s *Server) resourceIDFromRequest(r *http.Request) string {
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/scan-jobs/"):
		return strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/scan-jobs/"))
	case strings.HasPrefix(r.URL.Path, "/v1/auth/tokens/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/auth/tokens/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/policies/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/policies/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/policy-approvals/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/policy-approvals/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/remediations/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediations/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/remediation-exceptions/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediation-exceptions/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/remediation-assignments/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/remediation-assignments/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/notifications/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/notifications/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			return strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/findings/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/findings/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			path = strings.TrimSpace(path[:idx])
		}
		return path
	case strings.HasPrefix(r.URL.Path, "/v1/assets/"):
		path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/assets/"))
		if idx := strings.Index(path, "/"); idx >= 0 {
			path = strings.TrimSpace(path[:idx])
		}
		assetID, err := url.PathUnescape(path)
		if err != nil {
			return path
		}
		return strings.TrimSpace(assetID)
	default:
		return ""
	}
}

func (s *Server) extractAuthToken(r *http.Request) string {
	if token := auth.ParseBearerToken(r.Header.Get("Authorization")); token != "" {
		return token
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(cookie.Value)
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func (s *Server) writeMethodNotAllowed(w http.ResponseWriter) {
	s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "the requested method is not supported")
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	s.writeJSON(w, status, models.APIError{
		Code:    code,
		Message: message,
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

type auditedResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditedResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
