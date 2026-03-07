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

func TestPhase8ValidationWorkflowGatesRestrictedSteps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase8_validation_workflow_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase8-validation-workflow-secret"
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

	upsertEnvelopeResponse, upsertEnvelopeBody := mustJSONRequest(
		t,
		client,
		http.MethodPut,
		testServer.URL+"/v1/validation/envelopes/"+engagement.ID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"policy_pack_ref":        "phase8-workflow-pack-v1",
			"allowed_tools":          []string{"metasploit"},
			"requires_step_approval": true,
			"max_runtime_seconds":    300,
			"network_scope":          "approved-subnet",
		},
		http.StatusOK,
	)
	defer upsertEnvelopeResponse.Body.Close()

	var envelope models.ValidationExecutionEnvelope
	decodeJSONResponse(t, upsertEnvelopeBody, &envelope)
	if strings.TrimSpace(envelope.ID) == "" {
		t.Fatal("expected validation execution envelope id")
	}

	approveEnvelopeResponse, approveEnvelopeBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/validation/envelopes/"+engagement.ID+"/approve",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{"reason": "phase8 envelope approval"},
		http.StatusOK,
	)
	defer approveEnvelopeResponse.Body.Close()
	decodeJSONResponse(t, approveEnvelopeBody, &envelope)
	if envelope.Status != "approved" {
		t.Fatalf("expected approved validation execution envelope status, got %s", envelope.Status)
	}

	activateEnvelopeResponse, activateEnvelopeBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/validation/envelopes/"+engagement.ID+"/activate",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer activateEnvelopeResponse.Body.Close()
	decodeJSONResponse(t, activateEnvelopeBody, &envelope)
	if envelope.Status != "active" {
		t.Fatalf("expected active validation execution envelope status, got %s", envelope.Status)
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
			"name":        "Phase8 Workflow Domain Target",
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

	requiredStepResponse, requiredStepBody := mustJSONRequest(
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
		http.StatusBadRequest,
	)
	defer requiredStepResponse.Body.Close()
	var requiredStepPayload map[string]any
	decodeJSONResponse(t, requiredStepBody, &requiredStepPayload)
	if requiredStepPayload["code"] != "validation_plan_step_required" {
		t.Fatalf("expected validation_plan_step_required, got %#v", requiredStepPayload["code"])
	}

	createStepResponse, createStepBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/validation/plan-steps",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"engagement_id": engagement.ID,
			"name":          "Metasploit Approval Step",
			"adapter_id":    "metasploit",
			"target_kind":   "domain",
			"target":        "phase8.example.com",
		},
		http.StatusCreated,
	)
	defer createStepResponse.Body.Close()
	var step models.ValidationPlanStep
	decodeJSONResponse(t, createStepBody, &step)
	if strings.TrimSpace(step.ID) == "" {
		t.Fatal("expected validation plan step id")
	}

	pendingStepRunResponse, pendingStepRunBody := mustJSONRequest(
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
			"validation_plan_step_id":  step.ID,
		},
		http.StatusConflict,
	)
	defer pendingStepRunResponse.Body.Close()
	var pendingStepRunPayload map[string]any
	decodeJSONResponse(t, pendingStepRunBody, &pendingStepRunPayload)
	if pendingStepRunPayload["code"] != "validation_plan_step_not_approved" {
		t.Fatalf("expected validation_plan_step_not_approved, got %#v", pendingStepRunPayload["code"])
	}

	approveStepResponse, approveStepBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/validation/plan-steps/"+step.ID+"/approve",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{"reason": "step approved for controlled validation"},
		http.StatusOK,
	)
	defer approveStepResponse.Body.Close()
	decodeJSONResponse(t, approveStepBody, &step)
	if step.Status != "approved" {
		t.Fatalf("expected approved validation plan step status, got %s", step.Status)
	}

	allowedRunResponse, allowedRunBody := mustJSONRequest(
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
			"validation_plan_step_id":  step.ID,
		},
		http.StatusCreated,
	)
	defer allowedRunResponse.Body.Close()
	var allowedRunPayload struct {
		Target models.ScanTarget `json:"target"`
		Job    models.ScanJob    `json:"job"`
	}
	decodeJSONResponse(t, allowedRunBody, &allowedRunPayload)
	if strings.TrimSpace(allowedRunPayload.Job.ID) == "" {
		t.Fatal("expected scan job id")
	}

	workerLease := mustRegisterWorker(t, client, testServer.URL, cfg.WorkerSharedSecret)
	heartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, workerLease.WorkerID, workerLease.LeaseID)
	if len(heartbeat.Assignments) != 1 {
		t.Fatalf("expected 1 workflow-approved assignment, got %d", len(heartbeat.Assignments))
	}
	assignment := heartbeat.Assignments[0]
	if assignment.Labels["validation_execution_envelope_id"] != envelope.ID {
		t.Fatalf("expected envelope label %s, got %#v", envelope.ID, assignment.Labels["validation_execution_envelope_id"])
	}
	if assignment.Labels["validation_plan_step_id"] != step.ID {
		t.Fatalf("expected plan step label %s, got %#v", step.ID, assignment.Labels["validation_plan_step_id"])
	}
}
