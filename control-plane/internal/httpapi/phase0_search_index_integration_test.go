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

func TestPhase0SearchIndexFlowFindingsQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase0_search_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase0-search-secret"

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
	now := time.Date(2026, time.March, 6, 10, 0, 0, 0, time.UTC)

	taskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "repo",
		Target:     "c:/repos/core-service",
		Profile:    "balanced",
		Tools:      []string{"semgrep"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase0-search-worker",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "linux",
		Hostname:        "phase0-search-host",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "semgrep",
				SupportedTargetKinds: []string{"repo"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModePassive},
			},
		},
	})

	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:     taskID,
		WorkerID:   "phase0-search-worker",
		FinalState: "completed",
		ReportedFindings: []models.CanonicalFinding{
			{
				SchemaVersion: "1.0.0",
				Category:      "sast_rule_match",
				Title:         "SQL Injection in Query Builder",
				Description:   "Unsanitized user input reaches SQL query construction.",
				Severity:      "high",
				Confidence:    "high",
				Status:        "open",
				FirstSeenAt:   now,
				LastSeenAt:    now,
				Source: models.CanonicalSourceInfo{
					Layer: "code",
					Tool:  "semgrep",
				},
			},
		},
	}); err != nil {
		t.Fatalf("finalize search finding: %v", err)
	}

	response, body := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/search/findings?q=sql+injection&severity=high&layer=code&status=open&limit=10&offset=0", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer response.Body.Close()

	var payload models.FindingSearchResult
	decodeJSONResponse(t, body, &payload)
	if payload.Total != 1 {
		t.Fatalf("expected total=1 search result, got %d", payload.Total)
	}
	if len(payload.Items) != 1 {
		t.Fatalf("expected one search item, got %d", len(payload.Items))
	}
	if !strings.Contains(strings.ToLower(payload.Items[0].Title), "sql injection") {
		t.Fatalf("expected SQL injection search match, got %s", payload.Items[0].Title)
	}
}
