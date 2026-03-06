package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestPhase0EvidenceStorageAndRetentionFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase0_evidence_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase0-evidence-secret"

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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
	taskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "repo",
		Target:     "c:/repos/evidence-service",
		Profile:    "balanced",
		Tools:      []string{"semgrep"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase0-evidence-worker",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "linux",
		Hostname:        "phase0-evidence-host",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "semgrep",
				SupportedTargetKinds: []string{"repo"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModePassive},
			},
		},
	})

	evidencePath := filepath.Join(t.TempDir(), "semgrep-results.json")
	if err := os.WriteFile(evidencePath, []byte(`{"findings":[{"title":"hardcoded_secret"}]}`), 0o600); err != nil {
		t.Fatalf("write evidence fixture: %v", err)
	}

	now := time.Date(2026, time.March, 6, 12, 0, 0, 0, time.UTC)
	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:        taskID,
		WorkerID:      "phase0-evidence-worker",
		FinalState:    "completed",
		EvidencePaths: []string{evidencePath},
		ReportedFindings: []models.CanonicalFinding{
			{
				SchemaVersion: "1.0.0",
				Category:      "sast_rule_match",
				Title:         "Hardcoded credential",
				Severity:      "medium",
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
		t.Fatalf("finalize task with evidence: %v", err)
	}

	listResponse, listBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/evidence?task_id="+url.QueryEscape(taskID)+"&limit=10", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer listResponse.Body.Close()

	var listPayload models.EvidenceListResult
	decodeJSONResponse(t, listBody, &listPayload)
	if listPayload.Total != 1 || len(listPayload.Items) != 1 {
		t.Fatalf("expected one evidence object, got total=%d items=%d", listPayload.Total, len(listPayload.Items))
	}
	if listPayload.Items[0].ObjectRef != evidencePath {
		t.Fatalf("expected evidence object ref %s, got %s", evidencePath, listPayload.Items[0].ObjectRef)
	}
	if listPayload.Items[0].Archived {
		t.Fatalf("expected evidence object to start in hot tier, got archived=%v", listPayload.Items[0].Archived)
	}

	archiveBefore := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339Nano)
	runResponse, runBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/evidence/retention/run", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"archive_before": archiveBefore,
		"dry_run":        false,
	}, http.StatusOK)
	defer runResponse.Body.Close()

	var runPayload models.EvidenceRetentionRun
	decodeJSONResponse(t, runBody, &runPayload)
	if runPayload.ArchivedCount < 1 {
		t.Fatalf("expected at least one archived evidence object, got %d", runPayload.ArchivedCount)
	}

	archivedResponse, archivedBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/evidence?task_id="+url.QueryEscape(taskID)+"&archived=true&limit=10", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer archivedResponse.Body.Close()

	var archivedPayload models.EvidenceListResult
	decodeJSONResponse(t, archivedBody, &archivedPayload)
	if archivedPayload.Total < 1 || len(archivedPayload.Items) < 1 {
		t.Fatalf("expected archived evidence object after retention run, got total=%d", archivedPayload.Total)
	}
	if !archivedPayload.Items[0].Archived {
		t.Fatalf("expected archived evidence object, got %+v", archivedPayload.Items[0])
	}

	runsResponse, runsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/evidence/retention/runs?limit=5", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer runsResponse.Body.Close()

	var runsPayload struct {
		Items []models.EvidenceRetentionRun `json:"items"`
	}
	decodeJSONResponse(t, runsBody, &runsPayload)
	if len(runsPayload.Items) == 0 {
		t.Fatal("expected evidence retention run history")
	}
}
