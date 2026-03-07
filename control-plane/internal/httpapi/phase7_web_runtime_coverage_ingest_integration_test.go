package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestPhase7WebRuntimeCoverageIngestFromBrowserProbeEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase7_web_runtime_coverage_ingest_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase7-web-runtime-coverage-secret"
	cfg.KMSMasterKey = cfg.WorkerSharedSecret

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

	createTargetResponse, createTargetBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/web-targets", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":        "Phase7 Coverage Portal",
		"target_type": "webapp",
		"base_url":    "https://coverage.phase7.example.com",
	}, http.StatusCreated)
	defer createTargetResponse.Body.Close()

	var createdTarget models.WebTarget
	decodeJSONResponse(t, createTargetBody, &createdTarget)
	if strings.TrimSpace(createdTarget.ID) == "" {
		t.Fatal("expected created web target id")
	}

	upsertBaselineResponse, upsertBaselineBody := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/coverage-baseline", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"minimum_route_coverage": 75,
		"minimum_api_coverage":   60,
		"minimum_auth_coverage":  50,
		"notes":                  "auto-ingest baseline",
	}, http.StatusOK)
	defer upsertBaselineResponse.Body.Close()
	var baseline models.WebCoverageBaseline
	decodeJSONResponse(t, upsertBaselineBody, &baseline)
	if baseline.MinimumRouteCoverage != 75 {
		t.Fatalf("expected minimum_route_coverage=75, got %.1f", baseline.MinimumRouteCoverage)
	}

	runResponse, runBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/run",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"profile": "runtime",
			"tools":   []string{"browser-probe"},
		},
		http.StatusCreated,
	)
	defer runResponse.Body.Close()

	var runPayload struct {
		Target models.WebTarget `json:"target"`
		Job    models.ScanJob   `json:"job"`
	}
	decodeJSONResponse(t, runBody, &runPayload)
	if strings.TrimSpace(runPayload.Job.ID) == "" {
		t.Fatal("expected scan job id from web run")
	}

	workerRequest := models.WorkerRegistrationRequest{
		WorkerID:        "phase7-web-runtime-coverage-worker",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "linux",
		Hostname:        "phase7-web-runtime-coverage-host",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "browser-probe",
				SupportedTargetKinds: []string{"url"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModePassive, models.ExecutionModeActiveValidation},
				Labels:               []string{"phase7"},
				LinuxPreferred:       true,
			},
		},
	}

	registerResponse, registerBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/workers/register",
		"",
		auth.WorkerSecretHeader,
		cfg.WorkerSharedSecret,
		workerRequest,
		http.StatusOK,
	)
	defer registerResponse.Body.Close()

	var registerPayload models.WorkerRegistrationResponse
	decodeJSONResponse(t, registerBody, &registerPayload)
	if !registerPayload.Accepted {
		t.Fatal("expected worker registration to be accepted")
	}

	heartbeatResponse, heartbeatBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/workers/heartbeat",
		"",
		auth.WorkerSecretHeader,
		cfg.WorkerSharedSecret,
		models.HeartbeatRequest{
			WorkerID:      workerRequest.WorkerID,
			LeaseID:       registerPayload.LeaseID,
			TimestampUnix: time.Now().UTC().Unix(),
			Metrics: map[string]string{
				"phase": "7-coverage",
			},
		},
		http.StatusOK,
	)
	defer heartbeatResponse.Body.Close()

	var heartbeatPayload models.HeartbeatResponse
	decodeJSONResponse(t, heartbeatBody, &heartbeatPayload)
	if len(heartbeatPayload.Assignments) != 1 {
		t.Fatalf("expected 1 assignment, got %d", len(heartbeatPayload.Assignments))
	}

	assignment := heartbeatPayload.Assignments[0]
	if assignment.AdapterID != "browser-probe" {
		t.Fatalf("expected browser-probe assignment, got %s", assignment.AdapterID)
	}
	if assignment.Labels["web_target_id"] != createdTarget.ID {
		t.Fatalf("expected web_target_id label %s, got %#v", createdTarget.ID, assignment.Labels["web_target_id"])
	}

	evidenceDir := t.TempDir()
	evidencePath := filepath.Join(evidenceDir, "browser-probe-results.json")
	evidencePayload := `{
		"coverage": {
			"route_coverage": 88.5,
			"api_coverage": 72.0,
			"auth_coverage": 66.5,
			"discovered_route_count": 140,
			"discovered_api_operation_count": 58,
			"discovered_auth_state_count": 9
		},
		"findings": [
			{
				"id": "dom-xss-coverage-1",
				"rule_id": "dom-xss-reflected",
				"title": "Reflected DOM XSS sink reachable from query parameter",
				"category": "dom_xss",
				"severity": "high",
				"confidence": "high",
				"url": "https://coverage.phase7.example.com/search?q=test",
				"path": "/search",
				"line_number": 42
			}
		]
	}`
	if err := os.WriteFile(evidencePath, []byte(evidencePayload), 0o600); err != nil {
		t.Fatalf("write browser-probe evidence fixture: %v", err)
	}

	finalizeNow := time.Now().UTC()
	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:        assignment.JobID,
		WorkerID:      workerRequest.WorkerID,
		FinalState:    "completed",
		EvidencePaths: []string{evidencePath},
		ReportedFindings: []models.CanonicalFinding{
			{
				SchemaVersion: "1.0.0",
				Category:      "dom_xss",
				Title:         "Coverage ingest verification finding",
				Severity:      "high",
				Confidence:    "high",
				Status:        "open",
				FirstSeenAt:   finalizeNow,
				LastSeenAt:    finalizeNow,
				Source: models.CanonicalSourceInfo{
					Layer: "runtime",
					Tool:  "browser-probe",
				},
			},
		},
	}); err != nil {
		t.Fatalf("finalize browser-probe task: %v", err)
	}

	listCoverageRunsResponse, listCoverageRunsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/coverage-runs",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listCoverageRunsResponse.Body.Close()
	var listedCoverageRuns struct {
		Items []models.WebRuntimeCoverageRun `json:"items"`
	}
	decodeJSONResponse(t, listCoverageRunsBody, &listedCoverageRuns)
	if len(listedCoverageRuns.Items) != 1 {
		t.Fatalf("expected 1 coverage run, got %d", len(listedCoverageRuns.Items))
	}

	run := listedCoverageRuns.Items[0]
	if run.ScanJobID != runPayload.Job.ID {
		t.Fatalf("expected coverage run scan_job_id %s, got %s", runPayload.Job.ID, run.ScanJobID)
	}
	if run.RouteCoverage != 88.5 || run.APICoverage != 72 || run.AuthCoverage != 66.5 {
		t.Fatalf("unexpected coverage values: %#v", run)
	}
	if run.DiscoveredRouteCount != 140 || run.DiscoveredAPIOperationCount != 58 || run.DiscoveredAuthStateCount != 9 {
		t.Fatalf("unexpected discovered counts: %#v", run)
	}
	if run.EvidenceRef != evidencePath {
		t.Fatalf("expected coverage run evidence_ref %s, got %s", evidencePath, run.EvidenceRef)
	}

	coverageStatusResponse, coverageStatusBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/coverage-status",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer coverageStatusResponse.Body.Close()

	var coverageStatus models.WebCoverageStatus
	decodeJSONResponse(t, coverageStatusBody, &coverageStatus)
	if !coverageStatus.OverallMeets {
		t.Fatalf("expected coverage status overall_meets=true, got %#v", coverageStatus)
	}
	if coverageStatus.LatestRun == nil || coverageStatus.LatestRun.ID != run.ID {
		t.Fatalf("expected latest run %s, got %#v", run.ID, coverageStatus.LatestRun)
	}
}
