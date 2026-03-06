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

func TestPhase3ScanEngineControlsGateAndAnnotateTasks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase3_engine_controls_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase3-engine-controls-secret"

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

	disableResponse, _ := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/scan-engine-controls/metasploit", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"target_kind": "domain",
		"enabled":     false,
	}, http.StatusOK)
	defer disableResponse.Body.Close()

	deniedResponse, deniedBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/scan-jobs", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"target_kind": "domain",
		"target":      "phase3-controls.example.com",
		"profile":     "default",
		"tools":       []string{"metasploit"},
	}, http.StatusForbidden)
	defer deniedResponse.Body.Close()

	var deniedPayload map[string]any
	decodeJSONResponse(t, deniedBody, &deniedPayload)
	if deniedPayload["code"] != "engine_control_denied" {
		t.Fatalf("expected engine_control_denied code, got %#v", deniedPayload["code"])
	}

	enableResponse, enableBody := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/scan-engine-controls/metasploit", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"target_kind":         "domain",
		"enabled":             true,
		"rulepack_version":    "metasploit-pack-2026.03",
		"max_runtime_seconds": 180,
	}, http.StatusOK)
	defer enableResponse.Body.Close()

	var enabledControl models.ScanEngineControl
	decodeJSONResponse(t, enableBody, &enabledControl)
	if !enabledControl.Enabled {
		t.Fatal("expected enabled scan engine control")
	}
	if enabledControl.RulepackVersion != "metasploit-pack-2026.03" {
		t.Fatalf("expected rulepack version metasploit-pack-2026.03, got %s", enabledControl.RulepackVersion)
	}
	if enabledControl.MaxRuntimeSeconds != 180 {
		t.Fatalf("expected max runtime override 180, got %d", enabledControl.MaxRuntimeSeconds)
	}

	listResponse, listBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/scan-engine-controls?target_kind=domain&limit=20", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer listResponse.Body.Close()

	var listPayload struct {
		Items []models.ScanEngineControl `json:"items"`
	}
	decodeJSONResponse(t, listBody, &listPayload)
	if len(listPayload.Items) != 1 {
		t.Fatalf("expected 1 scan engine control item, got %d", len(listPayload.Items))
	}

	createJobResponse, createJobBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/scan-jobs", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"target_kind": "domain",
		"target":      "phase3-controls.example.com",
		"profile":     "default",
		"tools":       []string{"metasploit"},
	}, http.StatusCreated)
	defer createJobResponse.Body.Close()

	var createdJob models.ScanJob
	decodeJSONResponse(t, createJobBody, &createdJob)
	if strings.TrimSpace(createdJob.ID) == "" {
		t.Fatal("expected created scan job id")
	}

	worker := mustRegisterWorker(t, client, testServer.URL, cfg.WorkerSharedSecret)
	heartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, worker.WorkerID, worker.LeaseID)
	if len(heartbeat.Assignments) != 1 {
		t.Fatalf("expected 1 assignment, got %d", len(heartbeat.Assignments))
	}

	assignment := heartbeat.Assignments[0]
	if assignment.AdapterID != "metasploit" {
		t.Fatalf("expected metasploit assignment, got %s", assignment.AdapterID)
	}
	if assignment.MaxRuntimeSeconds != 180 {
		t.Fatalf("expected overridden max runtime 180, got %d", assignment.MaxRuntimeSeconds)
	}
	if assignment.Labels["rulepack_version"] != "metasploit-pack-2026.03" {
		t.Fatalf("expected rulepack label on assignment, got %#v", assignment.Labels["rulepack_version"])
	}
}
