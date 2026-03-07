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

func TestPhase8ValidationAttackTracesAndManualCoverageFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase8_validation_evidence_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase8-validation-evidence-secret"
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

	engagement := mustCreateAndActivateValidationEngagement(t, client, testServer.URL, cfg.BootstrapAdminToken)

	createTraceResponse, createTraceBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/validation/attack-traces",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"engagement_id": engagement.ID,
			"scan_job_id":   "job-phase8-trace-001",
			"task_id":       "task-phase8-trace-001",
			"adapter_id":    "metasploit",
			"target_kind":   "domain",
			"target":        "phase8.example.com",
			"title":         "Exploit Attempt Trace",
			"summary":       "restricted module execution attempt with replayable evidence",
			"severity":      "high",
			"evidence_refs": []string{"local://evidence/task-phase8-trace-001/output.json"},
			"artifacts": map[string]any{
				"screenshots": []string{"local://evidence/task-phase8-trace-001/shot-1.png"},
				"har":         []string{"local://evidence/task-phase8-trace-001/traffic.har"},
			},
			"replay_manifest": map[string]any{
				"steps": []map[string]any{
					{"kind": "http", "method": "GET", "url": "https://phase8.example.com"},
				},
			},
		},
		http.StatusCreated,
	)
	defer createTraceResponse.Body.Close()

	var createdTrace models.ValidationAttackTrace
	decodeJSONResponse(t, createTraceBody, &createdTrace)
	if strings.TrimSpace(createdTrace.ID) == "" {
		t.Fatal("expected created validation attack trace id")
	}
	if createdTrace.EngagementID != engagement.ID {
		t.Fatalf("expected engagement %s, got %s", engagement.ID, createdTrace.EngagementID)
	}

	listTraceResponse, listTraceBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/validation/attack-traces?engagement_id="+engagement.ID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listTraceResponse.Body.Close()
	var traceListPayload struct {
		Items []models.ValidationAttackTrace `json:"items"`
	}
	decodeJSONResponse(t, listTraceBody, &traceListPayload)
	if len(traceListPayload.Items) != 1 {
		t.Fatalf("expected 1 validation attack trace, got %d", len(traceListPayload.Items))
	}

	createManualResponse, createManualBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/validation/manual-tests",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"engagement_id": engagement.ID,
			"wstg_id":       "WSTG-INPV-01",
			"category":      "input-validation",
			"title":         "Test SQL injection controls",
			"status":        "in_progress",
			"assigned_to":   "appsec.tester@example.com",
			"notes":         "executing payload set A",
			"evidence_refs": []string{"local://evidence/manual/wstg-inpv-01-note.md"},
		},
		http.StatusCreated,
	)
	defer createManualResponse.Body.Close()

	var createdManual models.ValidationManualTestCase
	decodeJSONResponse(t, createManualBody, &createdManual)
	if strings.TrimSpace(createdManual.ID) == "" {
		t.Fatal("expected created validation manual test id")
	}
	if createdManual.Status != "in_progress" {
		t.Fatalf("expected in_progress status, got %s", createdManual.Status)
	}

	updateManualResponse, updateManualBody := mustJSONRequest(
		t,
		client,
		http.MethodPut,
		testServer.URL+"/v1/validation/manual-tests/"+createdManual.ID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"status": "passed",
			"notes":  "payload set A confirmed mitigated",
			"evidence_refs": []string{
				"local://evidence/manual/wstg-inpv-01-result.md",
			},
		},
		http.StatusOK,
	)
	defer updateManualResponse.Body.Close()

	var updatedManual models.ValidationManualTestCase
	decodeJSONResponse(t, updateManualBody, &updatedManual)
	if updatedManual.Status != "passed" {
		t.Fatalf("expected passed status, got %s", updatedManual.Status)
	}
	if updatedManual.CompletedAt == nil {
		t.Fatal("expected completed_at for passed manual test case")
	}

	listManualResponse, listManualBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/validation/manual-tests?engagement_id="+engagement.ID+"&status=passed",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listManualResponse.Body.Close()

	var manualListPayload struct {
		Items []models.ValidationManualTestCase `json:"items"`
	}
	decodeJSONResponse(t, listManualBody, &manualListPayload)
	if len(manualListPayload.Items) != 1 {
		t.Fatalf("expected 1 passed validation manual test case, got %d", len(manualListPayload.Items))
	}
	if manualListPayload.Items[0].ID != createdManual.ID {
		t.Fatalf("expected manual test id %s, got %s", createdManual.ID, manualListPayload.Items[0].ID)
	}
}

func mustCreateAndActivateValidationEngagement(t *testing.T, client *http.Client, baseURL string, token string) models.ValidationEngagement {
	t.Helper()

	createResponse, createBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		baseURL+"/v1/validation-engagements",
		token,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"name":          "Phase8 Evidence Engagement",
			"target_kind":   "domain",
			"target":        "phase8.example.com",
			"allowed_tools": []string{"metasploit", "nmap"},
		},
		http.StatusCreated,
	)
	defer createResponse.Body.Close()

	var engagement models.ValidationEngagement
	decodeJSONResponse(t, createBody, &engagement)

	approveResponse, approveBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		baseURL+"/v1/validation-engagements/"+engagement.ID+"/approve",
		token,
		auth.WorkerSecretHeader,
		"",
		map[string]any{"reason": "approved for test coverage"},
		http.StatusOK,
	)
	defer approveResponse.Body.Close()
	decodeJSONResponse(t, approveBody, &engagement)

	activateResponse, activateBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		baseURL+"/v1/validation-engagements/"+engagement.ID+"/activate",
		token,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer activateResponse.Body.Close()
	decodeJSONResponse(t, activateBody, &engagement)

	return engagement
}
