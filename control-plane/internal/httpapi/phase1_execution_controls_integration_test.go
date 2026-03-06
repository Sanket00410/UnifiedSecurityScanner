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

func TestPhase1ExecutionControlsAndTargetApprovalFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase1_execution_controls_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase1-execution-controls-secret"

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

	worker := mustRegisterWorker(t, client, testServer.URL, cfg.WorkerSharedSecret)

	disableControlsResponse, _ := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/tenant/execution-controls", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"emergency_stop_enabled": false,
		"maintenance_windows":    []map[string]any{},
	}, http.StatusOK)
	defer disableControlsResponse.Body.Close()

	_ = mustCreateScanJob(t, client, testServer.URL, cfg.BootstrapAdminToken, "phase1-maintenance-target.example.com", "metasploit", http.StatusCreated)

	dayCode := strings.ToLower(time.Now().UTC().Weekday().String()[:3])
	enableMaintenanceResponse, _ := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/tenant/execution-controls", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"maintenance_windows": []map[string]any{
			{
				"id":           "always-today",
				"name":         "Active Maintenance",
				"timezone":     "UTC",
				"days":         []string{dayCode},
				"start_hour":   0,
				"end_hour":     0,
				"target_kinds": []string{"domain"},
				"reason":       "planned maintenance",
			},
		},
	}, http.StatusOK)
	defer enableMaintenanceResponse.Body.Close()

	maintenanceHeartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, worker.WorkerID, worker.LeaseID)
	if len(maintenanceHeartbeat.Assignments) != 0 {
		t.Fatalf("expected no assignments during active maintenance window, got %d", len(maintenanceHeartbeat.Assignments))
	}

	disableMaintenanceResponse, _ := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/tenant/execution-controls", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"maintenance_windows": []map[string]any{},
	}, http.StatusOK)
	defer disableMaintenanceResponse.Body.Close()

	postMaintenanceHeartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, worker.WorkerID, worker.LeaseID)
	if len(postMaintenanceHeartbeat.Assignments) != 1 {
		t.Fatalf("expected one assignment after disabling maintenance window, got %d", len(postMaintenanceHeartbeat.Assignments))
	}

	enableEmergencyResponse, _ := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/tenant/execution-controls", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"emergency_stop_enabled": true,
		"emergency_stop_reason":  "incident response",
	}, http.StatusOK)
	defer enableEmergencyResponse.Body.Close()

	emergencyBlockedResponse, emergencyBlockedBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/scan-jobs", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"target_kind": "domain",
		"target":      "blocked.example.com",
		"profile":     "default",
		"tools":       []string{"metasploit"},
	}, http.StatusConflict)
	defer emergencyBlockedResponse.Body.Close()

	var emergencyPayload map[string]any
	decodeJSONResponse(t, emergencyBlockedBody, &emergencyPayload)
	if emergencyPayload["code"] != jobs.ExecutionControlEmergencyStop {
		t.Fatalf("expected %s code for emergency stop, got %#v", jobs.ExecutionControlEmergencyStop, emergencyPayload["code"])
	}

	disableEmergencyResponse, _ := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/tenant/execution-controls", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"emergency_stop_enabled": false,
		"emergency_stop_reason":  "",
	}, http.StatusOK)
	defer disableEmergencyResponse.Body.Close()

	enableRateLimitResponse, _ := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/tenant/operations", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"max_scan_jobs_per_minute": 2,
	}, http.StatusOK)
	defer enableRateLimitResponse.Body.Close()

	_ = mustCreateScanJob(t, client, testServer.URL, cfg.BootstrapAdminToken, "rate-limit-first.example.com", "metasploit", http.StatusCreated)

	rateLimitedResponse, rateLimitedBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/scan-jobs", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"target_kind": "domain",
		"target":      "rate-limit-second.example.com",
		"profile":     "default",
		"tools":       []string{"metasploit"},
	}, http.StatusTooManyRequests)
	defer rateLimitedResponse.Body.Close()

	var rateLimitedPayload map[string]any
	decodeJSONResponse(t, rateLimitedBody, &rateLimitedPayload)
	if rateLimitedPayload["code"] != "tenant_limit_exceeded" {
		t.Fatalf("expected tenant_limit_exceeded for rate limit, got %#v", rateLimitedPayload["code"])
	}
	if rateLimitedPayload["metric"] != "max_scan_jobs_per_minute" {
		t.Fatalf("expected metric max_scan_jobs_per_minute, got %#v", rateLimitedPayload["metric"])
	}

	disableRateLimitResponse, _ := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/tenant/operations", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"max_scan_jobs_per_minute": 0,
	}, http.StatusOK)
	defer disableRateLimitResponse.Body.Close()

	_ = mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, worker.WorkerID, worker.LeaseID)

	targetApprovalPolicyResponse, targetApprovalPolicyBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/policies", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":    "Target Approval Guardrail",
		"scope":   "global",
		"mode":    "enforce",
		"enabled": true,
		"rules": []map[string]any{
			{
				"effect": "require_approval",
				"field":  "target",
				"match":  "exact",
				"values": []string{"approval.example.com"},
			},
		},
	}, http.StatusCreated)
	defer targetApprovalPolicyResponse.Body.Close()

	var targetApprovalPolicy models.Policy
	decodeJSONResponse(t, targetApprovalPolicyBody, &targetApprovalPolicy)
	if len(targetApprovalPolicy.Rules) != 1 {
		t.Fatalf("expected 1 target approval policy rule, got %d", len(targetApprovalPolicy.Rules))
	}

	pendingApprovalJob := mustCreateScanJob(t, client, testServer.URL, cfg.BootstrapAdminToken, "approval.example.com", "metasploit", http.StatusCreated)
	if pendingApprovalJob.ApprovalMode != "manual-approval" {
		t.Fatalf("expected manual approval mode for target-based approval rule, got %s", pendingApprovalJob.ApprovalMode)
	}

	approvalGatedHeartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, worker.WorkerID, worker.LeaseID)
	if len(approvalGatedHeartbeat.Assignments) != 0 {
		t.Fatalf("expected no assignments while target-level approval is pending, got %d", len(approvalGatedHeartbeat.Assignments))
	}
}
