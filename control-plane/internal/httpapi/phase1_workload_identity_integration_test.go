package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestPhase1WorkerIdentityIssueAndRegisterFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase1_worker_identity_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = ""
	cfg.WorkloadIdentitySigningKey = "phase1-worker-identity-signing-key"
	cfg.WorkloadIdentityTTL = 90 * time.Minute

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

	issueResponse, issueBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/workload-identities/workers/issue", cfg.BootstrapAdminToken, "", "", map[string]any{
		"worker_id":   "phase1-worker-identity-1",
		"ttl_seconds": 1800,
	}, http.StatusCreated)
	defer issueResponse.Body.Close()

	var issued models.IssuedWorkerIdentityToken
	decodeJSONResponse(t, issueBody, &issued)
	if issued.Token == "" {
		t.Fatal("expected issued worker identity token")
	}

	registerRequest, err := http.NewRequest(http.MethodPost, testServer.URL+"/v1/workers/register", strings.NewReader(`{
		"worker_id":"phase1-worker-identity-1",
		"worker_version":"1.0.0",
		"operating_system":"linux",
		"hostname":"phase1-worker-host",
		"capabilities":[{"adapter_id":"semgrep","supported_target_kinds":["repo"],"supported_modes":["passive"]}]
	}`))
	if err != nil {
		t.Fatalf("build worker register request: %v", err)
	}
	registerRequest.Header.Set("Authorization", "Bearer "+issued.Token)
	registerRequest.Header.Set("Content-Type", "application/json")

	registerResponse, err := client.Do(registerRequest)
	if err != nil {
		t.Fatalf("execute worker register request: %v", err)
	}
	defer registerResponse.Body.Close()
	if registerResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for token-based worker register, got %d", registerResponse.StatusCode)
	}

	var registration models.WorkerRegistrationResponse
	if err := json.NewDecoder(registerResponse.Body).Decode(&registration); err != nil {
		t.Fatalf("decode worker register response: %v", err)
	}
	if strings.TrimSpace(registration.LeaseID) == "" {
		t.Fatal("expected lease id from worker register response")
	}

	heartbeatRequest, err := http.NewRequest(http.MethodPost, testServer.URL+"/v1/workers/heartbeat", strings.NewReader(fmt.Sprintf(`{
		"worker_id":"phase1-worker-identity-1",
		"lease_id":"%s",
		"timestamp_unix":%d,
		"metrics":{"cpu":"1","memory_mb":"64"}
	}`, registration.LeaseID, time.Now().UTC().Unix())))
	if err != nil {
		t.Fatalf("build worker heartbeat request: %v", err)
	}
	heartbeatRequest.Header.Set("Authorization", "Bearer "+issued.Token)
	heartbeatRequest.Header.Set("Content-Type", "application/json")

	heartbeatResponse, err := client.Do(heartbeatRequest)
	if err != nil {
		t.Fatalf("execute worker heartbeat request: %v", err)
	}
	defer heartbeatResponse.Body.Close()
	if heartbeatResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for token-based worker heartbeat, got %d", heartbeatResponse.StatusCode)
	}
}
