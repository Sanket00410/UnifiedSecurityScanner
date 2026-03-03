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

func TestPhase4RemediationWorkflowDerivesDueDateAndTransitions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase4_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase4-integration-secret"

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
	now := time.Date(2026, time.March, 3, 10, 0, 0, 0, time.UTC)

	taskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "domain",
		Target:     "verify.example.com",
		Profile:    "default",
		Tools:      []string{"zap"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase4-worker-zap",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "phase4-host-zap",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "zap",
				SupportedTargetKinds: []string{"domain"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModeActiveValidation},
			},
		},
	})

	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:     taskID,
		WorkerID:   "phase4-worker-zap",
		FinalState: "completed",
		ReportedFindings: []models.CanonicalFinding{
			{
				SchemaVersion: "1.0.0",
				Category:      "web_application_exposure",
				Title:         "Auth bypass",
				Severity:      "high",
				Confidence:    "high",
				Status:        "open",
				FirstSeenAt:   now,
				LastSeenAt:    now,
			},
		},
	}); err != nil {
		t.Fatalf("finalize phase4 finding: %v", err)
	}

	findingsResponse, findingsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/findings", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer findingsResponse.Body.Close()

	var findingsPayload struct {
		Items []models.CanonicalFinding `json:"items"`
	}
	decodeJSONResponse(t, findingsBody, &findingsPayload)
	if len(findingsPayload.Items) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findingsPayload.Items))
	}
	finding := findingsPayload.Items[0]
	if finding.Risk.SLADueAt == nil {
		t.Fatal("expected finding to include sla due date")
	}

	invalidTransitionResponse, invalidTransitionBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations/unknown/transition", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"status": "verified",
	}, http.StatusNotFound)
	defer invalidTransitionResponse.Body.Close()
	_ = invalidTransitionBody

	remediationResponse, remediationBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"finding_id": finding.FindingID,
		"title":      "Track auth bypass remediation",
		"owner":      "appsec-team",
	}, http.StatusCreated)
	defer remediationResponse.Body.Close()

	var remediation models.RemediationAction
	decodeJSONResponse(t, remediationBody, &remediation)
	if remediation.DueAt == nil {
		t.Fatal("expected remediation due_at to be derived")
	}
	if !remediation.DueAt.Equal(finding.Risk.SLADueAt.UTC()) {
		t.Fatalf("expected remediation due_at %s, got %s", finding.Risk.SLADueAt.UTC(), remediation.DueAt.UTC())
	}

	for _, status := range []string{"assigned", "in_progress", "ready_for_verify", "verified", "closed"} {
		transitionResponse, transitionBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations/"+remediation.ID+"/transition", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
			"status": status,
			"notes":  "phase4 transition to " + status,
		}, http.StatusOK)
		defer transitionResponse.Body.Close()

		decodeJSONResponse(t, transitionBody, &remediation)
		if remediation.Status != status {
			t.Fatalf("expected remediation status %s, got %s", status, remediation.Status)
		}
	}

	conflictResponse, conflictBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations/"+remediation.ID+"/transition", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"status": "in_progress",
	}, http.StatusConflict)
	defer conflictResponse.Body.Close()
	_ = conflictBody
}
