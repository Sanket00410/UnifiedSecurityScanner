package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestPhase2HTTPPostgresFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase2_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase2-integration-secret"

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

	policy := mustCreatePolicy(t, client, testServer.URL, cfg.BootstrapAdminToken)
	firstJob := mustCreateScanJob(t, client, testServer.URL, cfg.BootstrapAdminToken, "public.example.com", "metasploit", http.StatusCreated)
	if firstJob.ApprovalMode != "manual-approval" {
		t.Fatalf("expected manual approval mode, got %s", firstJob.ApprovalMode)
	}

	worker := mustRegisterWorker(t, client, testServer.URL, cfg.WorkerSharedSecret)
	initialHeartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, worker.WorkerID, worker.LeaseID)
	if len(initialHeartbeat.Assignments) != 0 {
		t.Fatalf("expected no assignments before approval, got %d", len(initialHeartbeat.Assignments))
	}

	approvals := mustListApprovals(t, client, testServer.URL, cfg.BootstrapAdminToken)
	if len(approvals.Items) != 1 {
		t.Fatalf("expected 1 approval request, got %d", len(approvals.Items))
	}
	if approvals.Items[0].Status != "pending" {
		t.Fatalf("expected pending approval, got %s", approvals.Items[0].Status)
	}

	approved := mustApprovePolicy(t, client, testServer.URL, cfg.BootstrapAdminToken, approvals.Items[0].ID)
	if approved.Status != "approved" {
		t.Fatalf("expected approved policy decision, got %s", approved.Status)
	}

	postApprovalHeartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, worker.WorkerID, worker.LeaseID)
	if len(postApprovalHeartbeat.Assignments) != 1 {
		t.Fatalf("expected 1 assignment after approval, got %d", len(postApprovalHeartbeat.Assignments))
	}
	if postApprovalHeartbeat.Assignments[0].AdapterID != "metasploit" {
		t.Fatalf("unexpected adapter assignment: %s", postApprovalHeartbeat.Assignments[0].AdapterID)
	}

	policy = mustUpdatePolicy(t, client, testServer.URL, cfg.BootstrapAdminToken, policy.ID)
	if policy.VersionNumber != 2 {
		t.Fatalf("expected version 2 after update, got %d", policy.VersionNumber)
	}
	if len(policy.Rules) != 2 {
		t.Fatalf("expected 2 rules after update, got %d", len(policy.Rules))
	}

	versions := mustListPolicyVersions(t, client, testServer.URL, cfg.BootstrapAdminToken, policy.ID)
	if len(versions.Items) < 2 {
		t.Fatalf("expected at least 2 policy versions, got %d", len(versions.Items))
	}
	if versions.Items[0].VersionNumber != 2 {
		t.Fatalf("expected newest policy version to be 2, got %d", versions.Items[0].VersionNumber)
	}

	mustCreateScanJobDenied(t, client, testServer.URL, cfg.BootstrapAdminToken, "blocked.example.com", "sqlmap")

	rolledBack := mustRollbackPolicy(t, client, testServer.URL, cfg.BootstrapAdminToken, policy.ID, 1)
	if len(rolledBack.Rules) != 1 {
		t.Fatalf("expected rollback to restore 1 rule, got %d", len(rolledBack.Rules))
	}

	_ = mustCreateScanJob(t, client, testServer.URL, cfg.BootstrapAdminToken, "service.internal", "metasploit", http.StatusCreated)
	exceptionHeartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, worker.WorkerID, worker.LeaseID)
	if len(exceptionHeartbeat.Assignments) != 1 {
		t.Fatalf("expected internal-target exception to dispatch immediately, got %d assignments", len(exceptionHeartbeat.Assignments))
	}
	if exceptionHeartbeat.Assignments[0].Target != "service.internal" {
		t.Fatalf("unexpected assignment target after exception flow: %s", exceptionHeartbeat.Assignments[0].Target)
	}
}

func mustCreatePolicy(t *testing.T, client *http.Client, baseURL string, token string) models.Policy {
	t.Helper()

	response, body := mustJSONRequest(t, client, http.MethodPost, baseURL+"/v1/policies", token, auth.WorkerSecretHeader, "", map[string]any{
		"name":    "Runtime Guardrail",
		"global":  true,
		"scope":   "global",
		"mode":    "enforce",
		"enabled": true,
		"rules": []map[string]any{
			{
				"effect": "require_approval",
				"field":  "tool",
				"match":  "exact",
				"values": []string{"metasploit"},
				"exceptions": []map[string]any{
					{
						"field":  "target",
						"match":  "suffix",
						"values": []string{".internal"},
					},
				},
			},
		},
	}, http.StatusCreated)
	defer response.Body.Close()

	var policy models.Policy
	decodeJSONResponse(t, body, &policy)
	if len(policy.Rules) != 1 {
		t.Fatalf("expected 1 structured rule, got %d", len(policy.Rules))
	}
	if len(policy.Rules[0].Exceptions) != 1 {
		t.Fatalf("expected 1 structured exception, got %d", len(policy.Rules[0].Exceptions))
	}
	return policy
}

func mustUpdatePolicy(t *testing.T, client *http.Client, baseURL string, token string, policyID string) models.Policy {
	t.Helper()

	response, body := mustJSONRequest(t, client, http.MethodPut, baseURL+"/v1/policies/"+policyID, token, auth.WorkerSecretHeader, "", map[string]any{
		"name":    "Runtime Guardrail",
		"scope":   "global",
		"mode":    "enforce",
		"enabled": true,
		"rules": []map[string]any{
			{
				"effect": "require_approval",
				"field":  "tool",
				"match":  "exact",
				"values": []string{"metasploit"},
				"exceptions": []map[string]any{
					{
						"field":  "target",
						"match":  "suffix",
						"values": []string{".internal"},
					},
				},
			},
			{
				"effect": "block",
				"field":  "tool",
				"match":  "exact",
				"values": []string{"sqlmap"},
			},
		},
	}, http.StatusOK)
	defer response.Body.Close()

	var policy models.Policy
	decodeJSONResponse(t, body, &policy)
	return policy
}

func mustRollbackPolicy(t *testing.T, client *http.Client, baseURL string, token string, policyID string, version int64) models.Policy {
	t.Helper()

	response, body := mustJSONRequest(t, client, http.MethodPost, baseURL+"/v1/policies/"+policyID+"/rollback", token, auth.WorkerSecretHeader, "", map[string]any{
		"version_number": version,
	}, http.StatusOK)
	defer response.Body.Close()

	var policy models.Policy
	decodeJSONResponse(t, body, &policy)
	return policy
}

func mustListPolicyVersions(t *testing.T, client *http.Client, baseURL string, token string, policyID string) struct {
	Items []models.PolicyVersion `json:"items"`
} {
	t.Helper()

	response, body := mustJSONRequest(t, client, http.MethodGet, baseURL+"/v1/policies/"+policyID+"/versions", token, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer response.Body.Close()

	var payload struct {
		Items []models.PolicyVersion `json:"items"`
	}
	decodeJSONResponse(t, body, &payload)
	return payload
}

func mustCreateScanJob(t *testing.T, client *http.Client, baseURL string, token string, target string, tool string, expectedStatus int) models.ScanJob {
	t.Helper()

	response, body := mustJSONRequest(t, client, http.MethodPost, baseURL+"/v1/scan-jobs", token, auth.WorkerSecretHeader, "", map[string]any{
		"target_kind": "domain",
		"target":      target,
		"profile":     "default",
		"tools":       []string{tool},
	}, expectedStatus)
	defer response.Body.Close()

	var job models.ScanJob
	decodeJSONResponse(t, body, &job)
	return job
}

func mustCreateScanJobDenied(t *testing.T, client *http.Client, baseURL string, token string, target string, tool string) {
	t.Helper()

	response, body := mustJSONRequest(t, client, http.MethodPost, baseURL+"/v1/scan-jobs", token, auth.WorkerSecretHeader, "", map[string]any{
		"target_kind": "domain",
		"target":      target,
		"profile":     "default",
		"tools":       []string{tool},
	}, http.StatusForbidden)
	defer response.Body.Close()

	var payload map[string]any
	decodeJSONResponse(t, body, &payload)
	if payload["code"] != "policy_denied" {
		t.Fatalf("expected policy_denied code, got %#v", payload["code"])
	}
}

func mustListApprovals(t *testing.T, client *http.Client, baseURL string, token string) struct {
	Items []models.PolicyApproval `json:"items"`
} {
	t.Helper()

	response, body := mustJSONRequest(t, client, http.MethodGet, baseURL+"/v1/policy-approvals", token, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer response.Body.Close()

	var payload struct {
		Items []models.PolicyApproval `json:"items"`
	}
	decodeJSONResponse(t, body, &payload)
	return payload
}

func mustApprovePolicy(t *testing.T, client *http.Client, baseURL string, token string, approvalID string) models.PolicyApproval {
	t.Helper()

	response, body := mustJSONRequest(t, client, http.MethodPost, baseURL+"/v1/policy-approvals/"+approvalID+"/approve", token, auth.WorkerSecretHeader, "", map[string]any{
		"reason": "approved-by-integration-test",
	}, http.StatusOK)
	defer response.Body.Close()

	var approval models.PolicyApproval
	decodeJSONResponse(t, body, &approval)
	return approval
}

type integrationWorkerLease struct {
	WorkerID string
	LeaseID  string
}

func mustRegisterWorker(t *testing.T, client *http.Client, baseURL string, workerSecret string) integrationWorkerLease {
	t.Helper()

	request := models.WorkerRegistrationRequest{
		WorkerID:        "integration-worker-1",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "integration-host",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "metasploit",
				SupportedTargetKinds: []string{"domain"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModeRestrictedExploit},
				Labels:               []string{"integration"},
				LinuxPreferred:       false,
			},
		},
	}

	response, body := mustJSONRequest(t, client, http.MethodPost, baseURL+"/v1/workers/register", "", auth.WorkerSecretHeader, workerSecret, request, http.StatusOK)
	defer response.Body.Close()

	var registration models.WorkerRegistrationResponse
	decodeJSONResponse(t, body, &registration)
	if !registration.Accepted {
		t.Fatal("expected worker registration to be accepted")
	}

	return integrationWorkerLease{
		WorkerID: request.WorkerID,
		LeaseID:  registration.LeaseID,
	}
}

func mustHeartbeat(t *testing.T, client *http.Client, baseURL string, workerSecret string, workerID string, leaseID string) models.HeartbeatResponse {
	t.Helper()

	response, body := mustJSONRequest(t, client, http.MethodPost, baseURL+"/v1/workers/heartbeat", "", auth.WorkerSecretHeader, workerSecret, models.HeartbeatRequest{
		WorkerID:      workerID,
		LeaseID:       leaseID,
		TimestampUnix: time.Now().UTC().Unix(),
		Metrics: map[string]string{
			"test": "true",
		},
	}, http.StatusOK)
	defer response.Body.Close()

	var heartbeat models.HeartbeatResponse
	decodeJSONResponse(t, body, &heartbeat)
	return heartbeat
}

func mustJSONRequest(
	t *testing.T,
	client *http.Client,
	method string,
	requestURL string,
	bearerToken string,
	extraHeader string,
	extraHeaderValue string,
	payload any,
	expectedStatus int,
) (*http.Response, []byte) {
	t.Helper()

	var bodyReader *bytes.Reader
	if payload == nil {
		bodyReader = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal request payload: %v", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequest(method, requestURL, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	if strings.TrimSpace(extraHeader) != "" && strings.TrimSpace(extraHeaderValue) != "" {
		request.Header.Set(extraHeader, extraHeaderValue)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("perform request %s %s: %v", method, requestURL, err)
	}

	body, err := readAllAndClose(response)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	response.Body = ioNopCloser(bytes.NewReader(body))
	if response.StatusCode != expectedStatus {
		t.Fatalf("expected HTTP %d for %s %s, got %d with body %s", expectedStatus, method, requestURL, response.StatusCode, string(body))
	}

	return response, body
}

func decodeJSONResponse(t *testing.T, body []byte, target any) {
	t.Helper()

	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode json response: %v; body=%s", err, string(body))
	}
}

func createIntegrationDatabase(t *testing.T, adminDatabaseURL string, databaseName string) (string, func()) {
	t.Helper()

	if !isSafeTestDatabaseName(databaseName) {
		t.Fatalf("unsafe integration database name: %s", databaseName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	adminConn, err := pgx.Connect(ctx, adminDatabaseURL)
	if err != nil {
		t.Skipf("postgres integration unavailable: %v", err)
	}
	defer adminConn.Close(context.Background())

	if _, err := adminConn.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatalf("create integration database: %v", err)
	}

	testDatabaseURL := mustReplaceDatabaseName(t, adminDatabaseURL, databaseName)
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()

		adminConn, err := pgx.Connect(cleanupCtx, adminDatabaseURL)
		if err != nil {
			t.Logf("reconnect admin database for cleanup: %v", err)
			return
		}
		defer adminConn.Close(context.Background())

		_, _ = adminConn.Exec(cleanupCtx, `
			SELECT pg_terminate_backend(pid)
			FROM pg_stat_activity
			WHERE datname = $1
			  AND pid <> pg_backend_pid()
		`, databaseName)
		if _, err := adminConn.Exec(cleanupCtx, "DROP DATABASE "+databaseName); err != nil {
			t.Logf("drop integration database %s: %v", databaseName, err)
		}
	}

	return testDatabaseURL, cleanup
}

func mustReplaceDatabaseName(t *testing.T, rawURL string, databaseName string) string {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse database url: %v", err)
	}

	parsed.Path = "/" + databaseName
	return parsed.String()
}

func isSafeTestDatabaseName(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

type readCloser struct {
	*bytes.Reader
}

func (r readCloser) Close() error {
	return nil
}

func ioNopCloser(reader *bytes.Reader) readCloser {
	return readCloser{Reader: reader}
}

func readAllAndClose(response *http.Response) ([]byte, error) {
	defer response.Body.Close()

	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(response.Body); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
