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

func TestPhase8ValidationEngagementsGateRestrictedDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase8_validation_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase8-validation-secret"
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

	createEngagementResponse, createEngagementBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/validation-engagements",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"name":          "Phase8 Restricted Validation Window",
			"target_kind":   "domain",
			"target":        "phase8.example.com",
			"allowed_tools": []string{"metasploit"},
		},
		http.StatusCreated,
	)
	defer createEngagementResponse.Body.Close()

	var engagement models.ValidationEngagement
	decodeJSONResponse(t, createEngagementBody, &engagement)
	if strings.TrimSpace(engagement.ID) == "" {
		t.Fatal("expected validation engagement id")
	}
	if engagement.Status != "draft" {
		t.Fatalf("expected draft engagement status, got %s", engagement.Status)
	}

	createTargetResponse, createTargetBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/scan-targets",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"name":        "Phase8 Domain Target",
			"target_kind": "domain",
			"target":      "phase8.example.com",
			"profile":     "default",
			"tools":       []string{"metasploit"},
		},
		http.StatusCreated,
	)
	defer createTargetResponse.Body.Close()

	var target models.ScanTarget
	decodeJSONResponse(t, createTargetBody, &target)
	if strings.TrimSpace(target.ID) == "" {
		t.Fatal("expected scan target id")
	}

	requiredResponse, requiredBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/scan-targets/"+target.ID+"/run",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"profile": "default",
			"tools":   []string{"metasploit"},
		},
		http.StatusBadRequest,
	)
	defer requiredResponse.Body.Close()

	var requiredPayload map[string]any
	decodeJSONResponse(t, requiredBody, &requiredPayload)
	if requiredPayload["code"] != "validation_engagement_required" {
		t.Fatalf("expected validation_engagement_required, got %#v", requiredPayload["code"])
	}

	approveResponse, approveBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/validation-engagements/"+engagement.ID+"/approve",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"reason": "phase8 approval",
		},
		http.StatusOK,
	)
	defer approveResponse.Body.Close()
	decodeJSONResponse(t, approveBody, &engagement)
	if engagement.Status != "approved" {
		t.Fatalf("expected approved engagement status, got %s", engagement.Status)
	}

	activateResponse, activateBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/validation-engagements/"+engagement.ID+"/activate",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer activateResponse.Body.Close()
	decodeJSONResponse(t, activateBody, &engagement)
	if engagement.Status != "active" {
		t.Fatalf("expected active engagement status, got %s", engagement.Status)
	}

	runAllowedResponse, runAllowedBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/scan-targets/"+target.ID+"/run",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"profile":                  "default",
			"tools":                    []string{"metasploit"},
			"validation_engagement_id": engagement.ID,
		},
		http.StatusCreated,
	)
	defer runAllowedResponse.Body.Close()
	var runAllowedPayload struct {
		Target models.ScanTarget `json:"target"`
		Job    models.ScanJob    `json:"job"`
	}
	decodeJSONResponse(t, runAllowedBody, &runAllowedPayload)
	if strings.TrimSpace(runAllowedPayload.Job.ID) == "" {
		t.Fatal("expected scan job id from run-scan-target response")
	}

	workerLease := mustRegisterWorker(t, client, testServer.URL, cfg.WorkerSharedSecret)
	firstHeartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, workerLease.WorkerID, workerLease.LeaseID)
	if len(firstHeartbeat.Assignments) != 1 {
		t.Fatalf("expected 1 assignment while engagement is active, got %d", len(firstHeartbeat.Assignments))
	}
	if firstHeartbeat.Assignments[0].AdapterID != "metasploit" {
		t.Fatalf("expected metasploit assignment, got %s", firstHeartbeat.Assignments[0].AdapterID)
	}
	if firstHeartbeat.Assignments[0].Labels["validation_engagement_id"] != engagement.ID {
		t.Fatalf("expected validation engagement label %s, got %#v", engagement.ID, firstHeartbeat.Assignments[0].Labels["validation_engagement_id"])
	}

	queuedResponse, queuedBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/scan-jobs",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"target_kind": "domain",
			"target":      "phase8.example.com",
			"profile":     "default",
			"tools":       []string{"metasploit"},
			"task_labels": map[string]any{
				"validation_engagement_id": engagement.ID,
			},
		},
		http.StatusCreated,
	)
	defer queuedResponse.Body.Close()
	var queuedJob models.ScanJob
	decodeJSONResponse(t, queuedBody, &queuedJob)
	if strings.TrimSpace(queuedJob.ID) == "" {
		t.Fatal("expected queued scan job id")
	}

	closeResponse, closeBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/validation-engagements/"+engagement.ID+"/close",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"reason": "phase8 window completed",
		},
		http.StatusOK,
	)
	defer closeResponse.Body.Close()
	decodeJSONResponse(t, closeBody, &engagement)
	if engagement.Status != "closed" {
		t.Fatalf("expected closed engagement status, got %s", engagement.Status)
	}

	blockedHeartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, workerLease.WorkerID, workerLease.LeaseID)
	if len(blockedHeartbeat.Assignments) != 0 {
		t.Fatalf("expected no assignments after engagement closure, got %d", len(blockedHeartbeat.Assignments))
	}

	inactiveResponse, inactiveBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/scan-jobs",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"target_kind": "domain",
			"target":      "phase8.example.com",
			"profile":     "default",
			"tools":       []string{"metasploit"},
			"task_labels": map[string]any{
				"validation_engagement_id": engagement.ID,
			},
		},
		http.StatusConflict,
	)
	defer inactiveResponse.Body.Close()
	var inactivePayload map[string]any
	decodeJSONResponse(t, inactiveBody, &inactivePayload)
	if inactivePayload["code"] != "validation_engagement_inactive" {
		t.Fatalf("expected validation_engagement_inactive, got %#v", inactivePayload["code"])
	}
}
