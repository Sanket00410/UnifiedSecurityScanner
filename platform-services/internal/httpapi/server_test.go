package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"unifiedsecurityscanner/platform-services/internal/config"
	"unifiedsecurityscanner/platform-services/internal/models"
)

type fakeStore struct {
	lastCreateJobRequest models.EnqueuePlatformJobRequest
	lastConnectorRequest models.CreateConnectorRequest
}

func (s *fakeStore) Ping(context.Context) error { return nil }
func (s *fakeStore) ResolveTenantID(raw string) string {
	if strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw)
	}
	return "bootstrap-org-local"
}

func (s *fakeStore) CreateConnector(_ context.Context, tenantID string, actor string, request models.CreateConnectorRequest) (models.Connector, error) {
	s.lastConnectorRequest = request
	return models.Connector{
		ID:            "connector-1",
		TenantID:      tenantID,
		Name:          request.Name,
		ConnectorKind: request.ConnectorKind,
	}, nil
}

func (s *fakeStore) ListConnectors(context.Context, string, string, int) ([]models.Connector, error) {
	return []models.Connector{}, nil
}

func (s *fakeStore) GetConnector(context.Context, string, string) (models.Connector, bool, error) {
	return models.Connector{
		ID:            "connector-1",
		TenantID:      "bootstrap-org-local",
		Name:          "jira-prod",
		ConnectorKind: models.ConnectorKindJira,
		Enabled:       true,
	}, true, nil
}

func (s *fakeStore) UpdateConnector(context.Context, string, string, string, models.UpdateConnectorRequest) (models.Connector, bool, error) {
	return models.Connector{}, false, nil
}

func (s *fakeStore) CreateJob(_ context.Context, tenantID string, actor string, request models.EnqueuePlatformJobRequest) (models.PlatformJob, error) {
	s.lastCreateJobRequest = request
	return models.PlatformJob{
		ID:          "platform-job-1",
		TenantID:    tenantID,
		JobKind:     request.JobKind,
		ConnectorID: request.ConnectorID,
		Payload:     request.Payload,
		Status:      models.JobStatusQueued,
	}, nil
}

func (s *fakeStore) ListJobs(context.Context, string, string, string, int) ([]models.PlatformJob, error) {
	return []models.PlatformJob{}, nil
}

func (s *fakeStore) GetJob(context.Context, string, string) (models.PlatformJob, bool, error) {
	return models.PlatformJob{}, false, nil
}

func (s *fakeStore) RetryJob(context.Context, string, string, string) (models.PlatformJob, bool, error) {
	return models.PlatformJob{}, false, nil
}

func (s *fakeStore) CreateNotification(context.Context, string, string, models.CreateNotificationRequest) (models.Notification, error) {
	return models.Notification{}, nil
}

func (s *fakeStore) ListNotifications(context.Context, string, string, int) ([]models.Notification, error) {
	return []models.Notification{}, nil
}

func (s *fakeStore) AcknowledgeNotification(context.Context, string, string, string) (models.Notification, bool, error) {
	return models.Notification{}, false, nil
}

func (s *fakeStore) CreateAuditExport(context.Context, string, string, models.CreateAuditExportRequest) (models.AuditExport, error) {
	return models.AuditExport{}, nil
}

func (s *fakeStore) ListAuditExports(context.Context, string, string, int) ([]models.AuditExport, error) {
	return []models.AuditExport{}, nil
}

func (s *fakeStore) CreateSyncRun(context.Context, string, string, models.CreateSyncRunRequest) (models.SyncRun, error) {
	return models.SyncRun{}, nil
}

func (s *fakeStore) ListSyncRuns(context.Context, string, string, string, int) ([]models.SyncRun, error) {
	return []models.SyncRun{}, nil
}

func (s *fakeStore) MetricsSnapshot(context.Context) (models.PlatformMetrics, error) {
	return models.PlatformMetrics{}, nil
}

func TestServerRequiresAuth(t *testing.T) {
	cfg := config.Load()
	cfg.APIAuthToken = "test-token"
	store := &fakeStore{}
	server := New(cfg, store)

	req := httptest.NewRequest(http.MethodGet, "/v1/jobs", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestCreateConnector(t *testing.T) {
	cfg := config.Load()
	cfg.APIAuthToken = "test-token"
	store := &fakeStore{}
	server := New(cfg, store)

	body := `{"name":"jira-main","connector_kind":"jira","endpoint_url":"https://jira.local/rest/api/2/issue"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/connectors", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(store.lastConnectorRequest.Name) != "jira-main" {
		t.Fatalf("expected connector request to be captured")
	}
}

func TestConnectorDispatchUsesDefaultKind(t *testing.T) {
	cfg := config.Load()
	cfg.APIAuthToken = "test-token"
	store := &fakeStore{}
	server := New(cfg, store)

	req := httptest.NewRequest(http.MethodPost, "/v1/connectors/connector-1/dispatch", strings.NewReader(`{"payload":{"title":"test finding"}}`))
	req.Header.Set("X-USS-API-Token", "test-token")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.lastCreateJobRequest.JobKind != models.JobKindJiraIssueUpsert {
		t.Fatalf("expected default jira job kind, got %s", store.lastCreateJobRequest.JobKind)
	}
	var response models.PlatformJob
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.JobKind != models.JobKindJiraIssueUpsert {
		t.Fatalf("expected response job kind %s, got %s", models.JobKindJiraIssueUpsert, response.JobKind)
	}
}
