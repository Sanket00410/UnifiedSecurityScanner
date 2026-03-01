package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

//go:embed static/*
var staticAssets embed.FS

type Server struct {
	cfg        config.Config
	httpServer *http.Server
	store      *jobs.Store
}

func New(cfg config.Config, store *jobs.Store) *Server {
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
	mux.HandleFunc("/v1/meta", server.handleMeta)
	mux.HandleFunc("/v1/scan-jobs", server.handleScanJobs)
	mux.HandleFunc("/v1/scan-jobs/", server.handleScanJobByID)
	mux.HandleFunc("/v1/findings", server.handleFindings)
	mux.HandleFunc("/v1/assets", server.handleAssets)
	mux.HandleFunc("/v1/policies", server.handlePolicies)
	mux.HandleFunc("/v1/remediations", server.handleRemediations)
	mux.HandleFunc("/v1/workers/register", server.handleWorkerRegister)
	mux.HandleFunc("/v1/workers/heartbeat", server.handleWorkerHeartbeat)
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

func (s *Server) handleScanJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jobsList, err := s.store.List(r.Context(), 100)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_scan_jobs_failed", "scan jobs could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": jobsList,
		})
	case http.MethodPost:
		s.createScanJob(w, r)
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

	job, ok, err := s.store.Get(r.Context(), jobID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "get_scan_job_failed", "scan job could not be loaded")
		return
	}
	if !ok {
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

	findings, err := s.store.ListFindings(r.Context(), 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_findings_failed", "findings could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": findings,
	})
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	assets, err := s.store.ListAssets(r.Context(), 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_assets_failed", "assets could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": assets,
	})
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policies, err := s.store.ListPolicies(r.Context(), 200)
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

		policy, err := s.store.CreatePolicy(r.Context(), request)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "create_policy_failed", "policy could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, policy)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleRemediations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListRemediations(r.Context(), 200)
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

		item, err := s.store.CreateRemediation(r.Context(), request)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "create_remediation_failed", "remediation action could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) createScanJob(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var request models.CreateScanJobRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	if strings.TrimSpace(request.TenantID) == "" ||
		strings.TrimSpace(request.TargetKind) == "" ||
		strings.TrimSpace(request.Target) == "" ||
		strings.TrimSpace(request.Profile) == "" ||
		strings.TrimSpace(request.RequestedBy) == "" {
		s.writeError(w, http.StatusBadRequest, "validation_error", "tenant_id, target_kind, target, profile, and requested_by are required")
		return
	}

	job, err := s.store.Create(r.Context(), request)
	if err != nil {
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
