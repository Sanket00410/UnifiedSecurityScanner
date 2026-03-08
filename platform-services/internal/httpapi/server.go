package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"unifiedsecurityscanner/platform-services/internal/config"
	"unifiedsecurityscanner/platform-services/internal/models"
	"unifiedsecurityscanner/platform-services/internal/store"
)

const (
	authHeaderBearer  = "Authorization"
	authHeaderToken   = "X-USS-API-Token"
	tenantHeader      = "X-USS-Tenant-ID"
	actorHeader       = "X-USS-Actor"
	defaultRouteActor = "platform-services-api"
)

type apiStore interface {
	Ping(ctx context.Context) error
	ResolveTenantID(raw string) string

	CreateConnector(ctx context.Context, tenantID string, actor string, request models.CreateConnectorRequest) (models.Connector, error)
	ListConnectors(ctx context.Context, tenantID string, kind string, limit int) ([]models.Connector, error)
	GetConnector(ctx context.Context, tenantID string, connectorID string) (models.Connector, bool, error)
	UpdateConnector(ctx context.Context, tenantID string, connectorID string, actor string, request models.UpdateConnectorRequest) (models.Connector, bool, error)

	CreateJob(ctx context.Context, tenantID string, actor string, request models.EnqueuePlatformJobRequest) (models.PlatformJob, error)
	ListJobs(ctx context.Context, tenantID string, status string, kind string, limit int) ([]models.PlatformJob, error)
	GetJob(ctx context.Context, tenantID string, jobID string) (models.PlatformJob, bool, error)
	RetryJob(ctx context.Context, tenantID string, jobID string, actor string) (models.PlatformJob, bool, error)

	CreateNotification(ctx context.Context, tenantID string, actor string, request models.CreateNotificationRequest) (models.Notification, error)
	ListNotifications(ctx context.Context, tenantID string, status string, limit int) ([]models.Notification, error)
	AcknowledgeNotification(ctx context.Context, tenantID string, notificationID string, actor string) (models.Notification, bool, error)

	CreateAuditExport(ctx context.Context, tenantID string, actor string, request models.CreateAuditExportRequest) (models.AuditExport, error)
	ListAuditExports(ctx context.Context, tenantID string, status string, limit int) ([]models.AuditExport, error)

	CreateSyncRun(ctx context.Context, tenantID string, actor string, request models.CreateSyncRunRequest) (models.SyncRun, error)
	ListSyncRuns(ctx context.Context, tenantID string, syncKind string, status string, limit int) ([]models.SyncRun, error)

	MetricsSnapshot(ctx context.Context) (models.PlatformMetrics, error)
}

type Server struct {
	cfg        config.Config
	store      apiStore
	httpServer *http.Server
}

func New(cfg config.Config, dataStore apiStore) *Server {
	mux := http.NewServeMux()
	server := &Server{
		cfg:   cfg,
		store: dataStore,
		httpServer: &http.Server{
			Addr:              cfg.APIBindAddress,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}

	mux.HandleFunc("/healthz", server.handleHealth)
	mux.HandleFunc("/readyz", server.handleReady)
	mux.HandleFunc("/metrics", server.handlePrometheusMetrics)
	mux.HandleFunc("/v1/metrics", server.withAuth(server.handleMetricsJSON))
	mux.HandleFunc("/v1/connectors", server.withAuth(server.handleConnectors))
	mux.HandleFunc("/v1/connectors/", server.withAuth(server.handleConnectorRoute))
	mux.HandleFunc("/v1/jobs", server.withAuth(server.handleJobs))
	mux.HandleFunc("/v1/jobs/", server.withAuth(server.handleJobRoute))
	mux.HandleFunc("/v1/notifications", server.withAuth(server.handleNotifications))
	mux.HandleFunc("/v1/notifications/", server.withAuth(server.handleNotificationRoute))
	mux.HandleFunc("/v1/audit-exports", server.withAuth(server.handleAuditExports))
	mux.HandleFunc("/v1/sync-runs", server.withAuth(server.handleSyncRuns))

	return server
}

func NewWithStore(cfg config.Config, dataStore *store.Store) *Server {
	return New(cfg, dataStore)
}

func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthorized(r) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "valid api token is required")
			return
		}
		next(w, r)
	}
}

func (s *Server) isAuthorized(r *http.Request) bool {
	expected := strings.TrimSpace(s.cfg.APIAuthToken)
	if expected == "" {
		return true
	}
	token := strings.TrimSpace(r.Header.Get(authHeaderToken))
	if token == "" {
		token = parseBearerToken(r.Header.Get(authHeaderBearer))
	}
	return token == expected
}

func parseBearerToken(headerValue string) string {
	value := strings.TrimSpace(headerValue)
	if value == "" {
		return ""
	}
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (s *Server) tenantID(r *http.Request) string {
	return s.store.ResolveTenantID(r.Header.Get(tenantHeader))
}

func (s *Server) actor(r *http.Request) string {
	actor := strings.TrimSpace(r.Header.Get(actorHeader))
	if actor == "" {
		return defaultRouteActor
	}
	return actor
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "platform-services-api",
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "database is not reachable")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ready",
		"service": "platform-services-api",
	})
}

func (s *Server) handleMetricsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	metrics, err := s.store.MetricsSnapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "metrics_failed", "metrics could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, metrics)
}

func (s *Server) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	metrics, err := s.store.MetricsSnapshot(r.Context())
	if err != nil {
		http.Error(w, "metrics_unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, "# HELP uss_platform_service_up platform services api health state\n")
	_, _ = fmt.Fprintf(w, "# TYPE uss_platform_service_up gauge\n")
	_, _ = fmt.Fprintf(w, "uss_platform_service_up 1\n")
	_, _ = fmt.Fprintf(w, "# HELP uss_platform_jobs_total total platform jobs grouped by status\n")
	_, _ = fmt.Fprintf(w, "# TYPE uss_platform_jobs_total gauge\n")
	for _, stat := range metrics.QueueStats {
		_, _ = fmt.Fprintf(w, "uss_platform_jobs_total{status=%q} %d\n", stat.Status, stat.Count)
	}
	_, _ = fmt.Fprintf(w, "# HELP uss_platform_notifications_open queued notifications\n")
	_, _ = fmt.Fprintf(w, "# TYPE uss_platform_notifications_open gauge\n")
	_, _ = fmt.Fprintf(w, "uss_platform_notifications_open %d\n", metrics.NotificationsOpen)
	_, _ = fmt.Fprintf(w, "# HELP uss_platform_audit_exports_pending pending audit exports\n")
	_, _ = fmt.Fprintf(w, "# TYPE uss_platform_audit_exports_pending gauge\n")
	_, _ = fmt.Fprintf(w, "uss_platform_audit_exports_pending %d\n", metrics.AuditExportsPending)
	_, _ = fmt.Fprintf(w, "# HELP uss_platform_sync_runs_pending pending sync runs\n")
	_, _ = fmt.Fprintf(w, "# TYPE uss_platform_sync_runs_pending gauge\n")
	_, _ = fmt.Fprintf(w, "uss_platform_sync_runs_pending %d\n", metrics.SyncRunsPending)
	_, _ = fmt.Fprintf(w, "# HELP uss_platform_connectors_enabled enabled connectors\n")
	_, _ = fmt.Fprintf(w, "# TYPE uss_platform_connectors_enabled gauge\n")
	_, _ = fmt.Fprintf(w, "uss_platform_connectors_enabled %d\n", metrics.ConnectorCount)
}

func (s *Server) handleConnectors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		kind := strings.TrimSpace(r.URL.Query().Get("kind"))
		limit := parseLimit(r.URL.Query().Get("limit"), 100)
		items, err := s.store.ListConnectors(r.Context(), s.tenantID(r), kind, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_connectors_failed", "connectors could not be loaded")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var request models.CreateConnectorRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		item, err := s.store.CreateConnector(r.Context(), s.tenantID(r), s.actor(r), request)
		if err != nil {
			writeError(w, http.StatusBadRequest, "create_connector_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, item)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleConnectorRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/connectors/"), "/")
	if path == "" {
		writeError(w, http.StatusNotFound, "connector_not_found", "connector route not found")
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) == 2 && parts[1] == "dispatch" {
		s.handleConnectorDispatch(w, r, parts[0])
		return
	}
	if len(parts) != 1 {
		writeError(w, http.StatusNotFound, "connector_route_not_found", "connector route not found")
		return
	}
	connectorID := parts[0]

	switch r.Method {
	case http.MethodGet:
		item, found, err := s.store.GetConnector(r.Context(), s.tenantID(r), connectorID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "get_connector_failed", "connector could not be loaded")
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "connector_not_found", "connector was not found")
			return
		}
		writeJSON(w, http.StatusOK, item)
	case http.MethodPut:
		var request models.UpdateConnectorRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		item, found, err := s.store.UpdateConnector(r.Context(), s.tenantID(r), connectorID, s.actor(r), request)
		if err != nil {
			writeError(w, http.StatusBadRequest, "update_connector_failed", err.Error())
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "connector_not_found", "connector was not found")
			return
		}
		writeJSON(w, http.StatusOK, item)
	default:
		writeMethodNotAllowed(w)
	}
}

type connectorDispatchRequest struct {
	JobKind   string         `json:"job_kind"`
	Payload   map[string]any `json:"payload"`
	NotBefore *time.Time     `json:"not_before,omitempty"`
}

func (s *Server) handleConnectorDispatch(w http.ResponseWriter, r *http.Request, connectorID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	connector, found, err := s.store.GetConnector(r.Context(), s.tenantID(r), connectorID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get_connector_failed", "connector could not be loaded")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "connector_not_found", "connector was not found")
		return
	}

	var request connectorDispatchRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	jobKind := strings.TrimSpace(request.JobKind)
	if jobKind == "" {
		jobKind = defaultConnectorJobKind(connector.ConnectorKind)
	}
	job, err := s.store.CreateJob(r.Context(), s.tenantID(r), s.actor(r), models.EnqueuePlatformJobRequest{
		JobKind:     jobKind,
		ConnectorID: connector.ID,
		Payload:     request.Payload,
		NotBefore:   request.NotBefore,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "enqueue_connector_job_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, job)
}

func defaultConnectorJobKind(connectorKind string) string {
	switch strings.TrimSpace(connectorKind) {
	case models.ConnectorKindJira:
		return models.JobKindJiraIssueUpsert
	case models.ConnectorKindServiceNow:
		return models.JobKindServiceNowIncident
	case models.ConnectorKindSIEM:
		return models.JobKindSIEMEventPush
	case models.ConnectorKindCMDB:
		return models.JobKindCMDBAssetUpsert
	default:
		return models.JobKindConnectorDispatch
	}
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		jobKind := strings.TrimSpace(r.URL.Query().Get("job_kind"))
		limit := parseLimit(r.URL.Query().Get("limit"), 100)
		items, err := s.store.ListJobs(r.Context(), s.tenantID(r), status, jobKind, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_jobs_failed", "jobs could not be loaded")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var request models.EnqueuePlatformJobRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		item, err := s.store.CreateJob(r.Context(), s.tenantID(r), s.actor(r), request)
		if err != nil {
			writeError(w, http.StatusBadRequest, "enqueue_job_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, item)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleJobRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/jobs/"), "/")
	if path == "" {
		writeError(w, http.StatusNotFound, "job_route_not_found", "job route not found")
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) == 2 && parts[1] == "retry" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		item, found, err := s.store.RetryJob(r.Context(), s.tenantID(r), parts[0], s.actor(r))
		if err != nil {
			writeError(w, http.StatusBadRequest, "retry_job_failed", err.Error())
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "job_not_found", "job was not found")
			return
		}
		writeJSON(w, http.StatusOK, item)
		return
	}
	if len(parts) != 1 {
		writeError(w, http.StatusNotFound, "job_route_not_found", "job route not found")
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	item, found, err := s.store.GetJob(r.Context(), s.tenantID(r), parts[0])
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get_job_failed", "job could not be loaded")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "job_not_found", "job was not found")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		limit := parseLimit(r.URL.Query().Get("limit"), 100)
		items, err := s.store.ListNotifications(r.Context(), s.tenantID(r), status, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_notifications_failed", "notifications could not be loaded")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var request models.CreateNotificationRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		item, err := s.store.CreateNotification(r.Context(), s.tenantID(r), s.actor(r), request)
		if err != nil {
			writeError(w, http.StatusBadRequest, "create_notification_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, item)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleNotificationRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/notifications/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[1] != "ack" {
		writeError(w, http.StatusNotFound, "notification_route_not_found", "notification route not found")
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	item, found, err := s.store.AcknowledgeNotification(r.Context(), s.tenantID(r), parts[0], s.actor(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ack_notification_failed", "notification could not be acknowledged")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "notification_not_found", "notification was not found")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleAuditExports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		limit := parseLimit(r.URL.Query().Get("limit"), 100)
		items, err := s.store.ListAuditExports(r.Context(), s.tenantID(r), status, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_audit_exports_failed", "audit exports could not be loaded")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var request models.CreateAuditExportRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		item, err := s.store.CreateAuditExport(r.Context(), s.tenantID(r), s.actor(r), request)
		if err != nil {
			writeError(w, http.StatusBadRequest, "create_audit_export_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, item)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleSyncRuns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		syncKind := strings.TrimSpace(r.URL.Query().Get("sync_kind"))
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		limit := parseLimit(r.URL.Query().Get("limit"), 100)
		items, err := s.store.ListSyncRuns(r.Context(), s.tenantID(r), syncKind, status, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_sync_runs_failed", "sync runs could not be loaded")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var request models.CreateSyncRunRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		item, err := s.store.CreateSyncRun(r.Context(), s.tenantID(r), s.actor(r), request)
		if err != nil {
			writeError(w, http.StatusBadRequest, "create_sync_run_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, item)
	default:
		writeMethodNotAllowed(w)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return false
	}
	return true
}

func parseLimit(raw string, fallback int) int {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]string{
		"code":    code,
		"message": message,
	})
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "the requested method is not supported")
}
