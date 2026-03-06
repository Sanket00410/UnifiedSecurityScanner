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

func TestPhase0Block1TenantLimitsAndEventStreamFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase0_block1_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase0-block1-secret"

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

	_, limitsBody := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/tenant/operations", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"max_total_scan_jobs":   1,
		"max_active_scan_jobs":  1,
		"max_scan_targets":      50,
		"max_ingestion_sources": 50,
	}, http.StatusOK)
	var limitsSnapshot models.TenantOperationsSnapshot
	decodeJSONResponse(t, limitsBody, &limitsSnapshot)
	if limitsSnapshot.Limits.MaxTotalScanJobs != 1 {
		t.Fatalf("expected total job limit 1, got %d", limitsSnapshot.Limits.MaxTotalScanJobs)
	}

	firstJob := mustCreateScanJob(t, client, testServer.URL, cfg.BootstrapAdminToken, "phase0-block1.example.com", "zap", http.StatusCreated)
	if firstJob.ID == "" {
		t.Fatal("expected first scan job id")
	}

	denyResponse, denyBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/scan-jobs", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"target_kind": "domain",
		"target":      "phase0-block1-second.example.com",
		"profile":     "default",
		"tools":       []string{"zap"},
	}, http.StatusTooManyRequests)
	defer denyResponse.Body.Close()

	var denyPayload map[string]any
	decodeJSONResponse(t, denyBody, &denyPayload)
	if denyPayload["code"] != "tenant_limit_exceeded" {
		t.Fatalf("expected tenant_limit_exceeded code, got %#v", denyPayload["code"])
	}

	opsResponse, opsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/tenant/operations", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer opsResponse.Body.Close()

	var opsSnapshot models.TenantOperationsSnapshot
	decodeJSONResponse(t, opsBody, &opsSnapshot)
	if opsSnapshot.Usage.TotalScanJobs != 1 {
		t.Fatalf("expected 1 total scan job usage, got %d", opsSnapshot.Usage.TotalScanJobs)
	}
	if opsSnapshot.Usage.ActiveScanJobs != 1 {
		t.Fatalf("expected 1 active scan job usage, got %d", opsSnapshot.Usage.ActiveScanJobs)
	}

	eventsResponse, eventsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/events?type=scan_job.created", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer eventsResponse.Body.Close()

	var eventsPayload struct {
		Items []models.PlatformEvent `json:"items"`
	}
	decodeJSONResponse(t, eventsBody, &eventsPayload)
	if len(eventsPayload.Items) == 0 {
		t.Fatal("expected at least one scan_job.created event")
	}
	if eventsPayload.Items[0].AggregateID == "" {
		t.Fatal("expected aggregate_id on platform event")
	}
}
