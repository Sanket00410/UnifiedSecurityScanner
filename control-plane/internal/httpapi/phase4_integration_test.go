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

	"github.com/jackc/pgx/v5"

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

func TestPhase4WorkflowTimelineRetestExceptionsAndTickets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase4_workflow_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase4-workflow-secret"

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
		Target:     "workflow.example.com",
		Profile:    "default",
		Tools:      []string{"zap"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase4-workflow-worker",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "phase4-workflow-host",
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
		WorkerID:   "phase4-workflow-worker",
		FinalState: "completed",
		ReportedFindings: []models.CanonicalFinding{
			{
				SchemaVersion: "1.0.0",
				Category:      "web_application_exposure",
				Title:         "Workflow SQL injection",
				Severity:      "high",
				Confidence:    "high",
				Status:        "open",
				FirstSeenAt:   now,
				LastSeenAt:    now,
			},
		},
	}); err != nil {
		t.Fatalf("finalize workflow finding: %v", err)
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

	conn, err := pgx.Connect(ctx, testDatabaseURL)
	if err != nil {
		t.Fatalf("connect to integration database: %v", err)
	}
	_, err = conn.Exec(ctx, `
		UPDATE normalized_findings
		SET current_status = 'resolved',
		    finding_json = jsonb_set(finding_json, '{status}', '"resolved"'::jsonb),
		    updated_at = NOW()
		WHERE tenant_id = $1
	`, "bootstrap-org-local")
	_ = conn.Close(ctx)
	if err != nil {
		t.Fatalf("mark workflow finding resolved: %v", err)
	}

	remediationResponse, remediationBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"finding_id": finding.FindingID,
		"title":      "Workflow remediation",
		"owner":      "workflow-team",
	}, http.StatusCreated)
	defer remediationResponse.Body.Close()

	var remediation models.RemediationAction
	decodeJSONResponse(t, remediationBody, &remediation)

	commentResponse, commentBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations/"+remediation.ID+"/comments", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"comment": "initial remediation note",
	}, http.StatusCreated)
	defer commentResponse.Body.Close()
	_ = commentBody

	for _, status := range []string{"assigned", "in_progress", "ready_for_verify"} {
		transitionResponse, transitionBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations/"+remediation.ID+"/transition", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
			"status": status,
			"notes":  "transition to " + status,
		}, http.StatusOK)
		defer transitionResponse.Body.Close()
		decodeJSONResponse(t, transitionBody, &remediation)
	}

	retestResponse, retestBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations/"+remediation.ID+"/retest", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"notes": "run retest after code fix",
	}, http.StatusCreated)
	defer retestResponse.Body.Close()

	var retestPayload struct {
		Verification models.RemediationVerification `json:"verification"`
		ScanJob      models.ScanJob                 `json:"scan_job"`
	}
	decodeJSONResponse(t, retestBody, &retestPayload)
	if retestPayload.Verification.ID == "" || retestPayload.ScanJob.ID == "" {
		t.Fatal("expected retest verification and scan job ids")
	}

	verificationsResponse, verificationsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/remediations/"+remediation.ID+"/verifications", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer verificationsResponse.Body.Close()

	var verificationsPayload struct {
		Items []models.RemediationVerification `json:"items"`
	}
	decodeJSONResponse(t, verificationsBody, &verificationsPayload)
	if len(verificationsPayload.Items) != 1 {
		t.Fatalf("expected 1 remediation verification, got %d", len(verificationsPayload.Items))
	}

	verifyResponse, verifyBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations/"+remediation.ID+"/verify", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"verification_id": retestPayload.Verification.ID,
		"outcome":         "failed",
		"notes":           "issue still reproduces",
	}, http.StatusOK)
	defer verifyResponse.Body.Close()

	var completedVerification models.RemediationVerification
	decodeJSONResponse(t, verifyBody, &completedVerification)
	if completedVerification.Outcome != "failed" {
		t.Fatalf("expected failed verification outcome, got %s", completedVerification.Outcome)
	}

	updatedRemediationResponse, updatedRemediationBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/remediations/"+remediation.ID, cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer updatedRemediationResponse.Body.Close()
	decodeJSONResponse(t, updatedRemediationBody, &remediation)
	if remediation.Status != "in_progress" {
		t.Fatalf("expected remediation to return to in_progress, got %s", remediation.Status)
	}

	findingsAfterVerifyResponse, findingsAfterVerifyBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/findings", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer findingsAfterVerifyResponse.Body.Close()
	decodeJSONResponse(t, findingsAfterVerifyBody, &findingsPayload)
	if findingsPayload.Items[0].Status != "open" {
		t.Fatalf("expected finding to reopen, got %s", findingsPayload.Items[0].Status)
	}
	if findingsPayload.Items[0].ReopenedCount != 1 {
		t.Fatalf("expected reopened_count 1 after failed verification, got %d", findingsPayload.Items[0].ReopenedCount)
	}

	exceptionResponse, exceptionBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations/"+remediation.ID+"/exceptions", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"reason":    "business-approved risk acceptance",
		"reduction": 15,
		"notes":     "temporary exception until quarter end",
	}, http.StatusCreated)
	defer exceptionResponse.Body.Close()

	var exception models.RemediationException
	decodeJSONResponse(t, exceptionBody, &exception)
	if exception.Status != "pending" {
		t.Fatalf("expected pending remediation exception, got %s", exception.Status)
	}

	approveExceptionResponse, approveExceptionBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediation-exceptions/"+exception.ID+"/approve", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"reason": "approved by risk committee",
	}, http.StatusOK)
	defer approveExceptionResponse.Body.Close()
	decodeJSONResponse(t, approveExceptionBody, &exception)
	if exception.Status != "approved" {
		t.Fatalf("expected approved remediation exception, got %s", exception.Status)
	}

	findingsAfterExceptionResponse, findingsAfterExceptionBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/findings", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer findingsAfterExceptionResponse.Body.Close()
	decodeJSONResponse(t, findingsAfterExceptionBody, &findingsPayload)
	if findingsPayload.Items[0].Risk.WaiverReduction < 15 {
		t.Fatalf("expected waiver reduction after approved exception, got %.2f", findingsPayload.Items[0].Risk.WaiverReduction)
	}

	ticketResponse, ticketBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations/"+remediation.ID+"/tickets", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"provider":    "jira",
		"external_id": "APPSEC-42",
		"title":       "Workflow remediation ticket",
		"url":         "https://jira.example.com/browse/APPSEC-42",
		"status":      "open",
	}, http.StatusCreated)
	defer ticketResponse.Body.Close()

	var ticket models.RemediationTicketLink
	decodeJSONResponse(t, ticketBody, &ticket)
	if ticket.Provider != "jira" {
		t.Fatalf("expected jira provider, got %s", ticket.Provider)
	}

	ticketsResponse, ticketsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/remediations/"+remediation.ID+"/tickets", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer ticketsResponse.Body.Close()

	var ticketsPayload struct {
		Items []models.RemediationTicketLink `json:"items"`
	}
	decodeJSONResponse(t, ticketsBody, &ticketsPayload)
	if len(ticketsPayload.Items) != 1 {
		t.Fatalf("expected 1 remediation ticket link, got %d", len(ticketsPayload.Items))
	}

	activityResponse, activityBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/remediations/"+remediation.ID+"/activity", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer activityResponse.Body.Close()

	var activityPayload struct {
		Items []models.RemediationActivity `json:"items"`
	}
	decodeJSONResponse(t, activityBody, &activityPayload)
	if len(activityPayload.Items) < 7 {
		t.Fatalf("expected multiple remediation activity entries, got %d", len(activityPayload.Items))
	}
}
