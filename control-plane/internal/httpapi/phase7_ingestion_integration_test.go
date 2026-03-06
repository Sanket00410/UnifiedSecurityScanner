package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestPhase7IngestionWebhookNormalizesProviderHeadersAndPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase7_ingestion_normalization_it_%d", time.Now().UTC().UnixNano())
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
		"name":        "GitHub Service",
		"provider":    "github",
		"target_kind": "repo",
		"target":      "https://github.com/acme/service",
		"profile":     "balanced",
		"tools":       []string{"semgrep", "trivy"},
		"labels": map[string]any{
			"team": "appsec",
		},
	}, http.StatusCreated)
	defer createSourceResponse.Body.Close()

	var createdSource models.CreatedIngestionSource
	decodeJSONResponse(t, createSourceBody, &createdSource)

	bodyPayload := map[string]any{
		"payload": map[string]any{
			"ref":   "refs/heads/feature/phase7",
			"after": "cafef00d",
			"repository": map[string]any{
				"full_name": "acme/service",
			},
			"sender": map[string]any{
				"login": "phase7-bot",
			},
		},
	}
	encodedBody, err := json.Marshal(bodyPayload)
	if err != nil {
		t.Fatalf("marshal webhook payload: %v", err)
	}

	webhookRequest, err := http.NewRequest(http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, bytes.NewReader(encodedBody))
	if err != nil {
		t.Fatalf("create webhook request: %v", err)
	}
	webhookRequest.Header.Set("Content-Type", "application/json")
	webhookRequest.Header.Set("Authorization", "Bearer "+createdSource.IngestToken)
	webhookRequest.Header.Set("X-GitHub-Event", "push")
	webhookRequest.Header.Set("X-GitHub-Delivery", "gh-provider-evt-009")

	webhookResponse, err := client.Do(webhookRequest)
	if err != nil {
		t.Fatalf("execute webhook request: %v", err)
	}
	webhookBody, err := readAllAndClose(webhookResponse)
	if err != nil {
		t.Fatalf("read webhook response body: %v", err)
	}
	if webhookResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("expected webhook to be accepted, got %d body=%s", webhookResponse.StatusCode, string(webhookBody))
	}

	var accepted models.IngestionWebhookResponse
	decodeJSONResponse(t, webhookBody, &accepted)
	if accepted.Duplicate {
		t.Fatal("expected provider normalization event to be non-duplicate")
	}
	if accepted.Event.EventType != "github.push" {
		t.Fatalf("expected event type github.push, got %s", accepted.Event.EventType)
	}
	if accepted.Event.ExternalID != "gh-provider-evt-009" {
		t.Fatalf("expected external id from header, got %s", accepted.Event.ExternalID)
	}

	eventsResponse, eventsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/ingestion/events?source_id="+createdSource.Source.ID, cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer eventsResponse.Body.Close()

	var eventsPayload struct {
		Items []models.IngestionEvent `json:"items"`
	}
	decodeJSONResponse(t, eventsBody, &eventsPayload)
	if len(eventsPayload.Items) != 1 {
		t.Fatalf("expected one ingestion event, got %d", len(eventsPayload.Items))
	}

	stored := eventsPayload.Items[0]
	if strings.TrimSpace(stored.CreatedScanJobID) == "" {
		t.Fatal("expected created scan job id on normalized ingestion event")
	}

	labels, ok := stored.Payload["labels"].(map[string]any)
	if !ok {
		t.Fatalf("expected labels map in payload, got %#v", stored.Payload["labels"])
	}
	if labels["repo"] != "acme/service" {
		t.Fatalf("expected repo label from provider payload, got %#v", labels["repo"])
	}
	if labels["branch"] != "feature/phase7" {
		t.Fatalf("expected branch label from provider payload, got %#v", labels["branch"])
	}
	if labels["commit"] != "cafef00d" {
		t.Fatalf("expected commit label from provider payload, got %#v", labels["commit"])
	}
	if labels["team"] != "appsec" {
		t.Fatalf("expected source label to be preserved, got %#v", labels["team"])
	}

	metadata, ok := stored.Payload["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map in payload, got %#v", stored.Payload["metadata"])
	}
	if metadata["provider"] != "github" {
		t.Fatalf("expected provider metadata github, got %#v", metadata["provider"])
	}
	if metadata["sender"] != "phase7-bot" {
		t.Fatalf("expected sender metadata phase7-bot, got %#v", metadata["sender"])
	}
	headers, ok := metadata["webhook_headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected webhook headers metadata, got %#v", metadata["webhook_headers"])
	}
	if headers["x-github-event"] != "push" {
		t.Fatalf("expected x-github-event header in metadata, got %#v", headers["x-github-event"])
	}
	if headers["x-github-delivery"] != "gh-provider-evt-009" {
		t.Fatalf("expected x-github-delivery header in metadata, got %#v", headers["x-github-delivery"])
	}
}
