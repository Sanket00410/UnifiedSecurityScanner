package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestPhase7IngestionWebhookFlowCreatesAndReplaysEvents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase7_ingestion_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase7-ingestion-secret"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, err := jobs.NewStore(ctx, cfg)
	if err != nil {
		t.Fatalf("create integration store: %v", err)
	}
	defer store.Close()

	server := New(cfg, store)
	testServer := httptest.NewServer(server.httpServer.Handler)
	defer testServer.Close()

	client := testServer.Client()

	createSourceResponse, createSourceBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/ingestion/sources", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":        "GitHub Core Repo",
		"provider":    "github",
		"target_kind": "repo",
		"target":      "https://github.com/acme/core",
		"profile":     "balanced",
		"tools":       []string{"semgrep", "trivy", "gitleaks"},
		"labels": map[string]any{
			"repo": "acme/core",
		},
	}, http.StatusCreated)
	defer createSourceResponse.Body.Close()

	var createdSource models.CreatedIngestionSource
	decodeJSONResponse(t, createSourceBody, &createdSource)
	if strings.TrimSpace(createdSource.Source.ID) == "" {
		t.Fatal("expected ingestion source id")
	}
	if strings.TrimSpace(createdSource.IngestToken) == "" {
		t.Fatal("expected ingestion source token")
	}

	webhookResponse, webhookBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, "", ingestionTokenHeader, createdSource.IngestToken, map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-gh-001",
		"requested_by": "github-webhook",
	}, http.StatusAccepted)
	defer webhookResponse.Body.Close()

	var accepted models.IngestionWebhookResponse
	decodeJSONResponse(t, webhookBody, &accepted)
	if accepted.Duplicate {
		t.Fatal("expected first webhook event to be non-duplicate")
	}
	if accepted.Event.Status != "queued" {
		t.Fatalf("expected queued ingestion status, got %s", accepted.Event.Status)
	}
	if accepted.Job == nil || strings.TrimSpace(accepted.Job.ID) == "" {
		t.Fatal("expected webhook to create a scan job")
	}

	scanJobsResponse, scanJobsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/scan-jobs", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer scanJobsResponse.Body.Close()

	var scanJobsPayload struct {
		Items []models.ScanJob `json:"items"`
	}
	decodeJSONResponse(t, scanJobsBody, &scanJobsPayload)
	if len(scanJobsPayload.Items) != 1 {
		t.Fatalf("expected exactly one scan job after first webhook, got %d", len(scanJobsPayload.Items))
	}
	if scanJobsPayload.Items[0].ID != accepted.Job.ID {
		t.Fatalf("expected scan job %s, got %s", accepted.Job.ID, scanJobsPayload.Items[0].ID)
	}

	replayResponse, replayBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, "", ingestionTokenHeader, createdSource.IngestToken, map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-gh-001",
		"requested_by": "github-webhook",
	}, http.StatusOK)
	defer replayResponse.Body.Close()

	var replayed models.IngestionWebhookResponse
	decodeJSONResponse(t, replayBody, &replayed)
	if !replayed.Duplicate {
		t.Fatal("expected replayed webhook to be marked duplicate")
	}
	if replayed.Event.ID != accepted.Event.ID {
		t.Fatalf("expected duplicate event id %s, got %s", accepted.Event.ID, replayed.Event.ID)
	}
	if replayed.Job == nil || replayed.Job.ID != accepted.Job.ID {
		t.Fatalf("expected duplicate replay job id %s, got %#v", accepted.Job.ID, replayed.Job)
	}

	eventsResponse, eventsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/ingestion/events?source_id="+createdSource.Source.ID, cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer eventsResponse.Body.Close()

	var eventsPayload struct {
		Items []models.IngestionEvent `json:"items"`
	}
	decodeJSONResponse(t, eventsBody, &eventsPayload)
	if len(eventsPayload.Items) != 1 {
		t.Fatalf("expected one deduplicated ingestion event, got %d", len(eventsPayload.Items))
	}
	if eventsPayload.Items[0].CreatedScanJobID != accepted.Job.ID {
		t.Fatalf("expected ingestion event to reference job %s, got %s", accepted.Job.ID, eventsPayload.Items[0].CreatedScanJobID)
	}
}
