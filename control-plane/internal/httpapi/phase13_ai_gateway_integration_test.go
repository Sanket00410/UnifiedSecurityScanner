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

func TestPhase13AIGatewayPolicyAndTriageFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase13_ai_gateway_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase13-ai-gateway-secret"
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

	getPolicyResponse, getPolicyBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/ai/policy",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer getPolicyResponse.Body.Close()
	var policy models.AIGatewayPolicy
	decodeJSONResponse(t, getPolicyBody, &policy)
	if strings.TrimSpace(policy.DefaultModel) == "" {
		t.Fatal("expected default ai model in policy")
	}

	maxInput := int64(16000)
	maxOutput := int64(3500)
	updatePolicyResponse, updatePolicyBody := mustJSONRequest(
		t,
		client,
		http.MethodPut,
		testServer.URL+"/v1/ai/policy",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"default_model":         "gpt-4o-mini",
			"allowed_models":        []string{"gpt-4o-mini"},
			"max_input_chars":       maxInput,
			"max_output_chars":      maxOutput,
			"require_grounding":     true,
			"require_evidence_refs": true,
			"redact_secrets":        true,
		},
		http.StatusOK,
	)
	defer updatePolicyResponse.Body.Close()
	decodeJSONResponse(t, updatePolicyBody, &policy)
	if policy.MaxInputChars != maxInput {
		t.Fatalf("expected max_input_chars %d, got %d", maxInput, policy.MaxInputChars)
	}

	missingEvidenceResponse, missingEvidenceBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/ai/triage/summaries",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"model":      "gpt-4o-mini",
			"input_text": "Summarize finding without evidence refs",
		},
		http.StatusBadRequest,
	)
	defer missingEvidenceResponse.Body.Close()
	var missingEvidencePayload map[string]any
	decodeJSONResponse(t, missingEvidenceBody, &missingEvidencePayload)
	if missingEvidencePayload["code"] != "ai_evidence_required" {
		t.Fatalf("expected ai_evidence_required, got %#v", missingEvidencePayload["code"])
	}

	createSummaryResponse, createSummaryBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/ai/triage/summaries",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"model":         "gpt-4o-mini",
			"input_text":    "Summarize replay finding for callback endpoint password=secret-value",
			"evidence_refs": []string{"local://evidence/runtime/waf-block-001.json"},
			"finding_ids":   []string{"finding-runtime-replay-001"},
		},
		http.StatusCreated,
	)
	defer createSummaryResponse.Body.Close()
	var triage models.AITriageRequest
	decodeJSONResponse(t, createSummaryBody, &triage)
	if strings.TrimSpace(triage.ID) == "" {
		t.Fatal("expected ai triage request id")
	}
	if !strings.Contains(triage.ResponseText, "Evidence-grounded summary only.") {
		t.Fatalf("expected grounded summary text, got %s", triage.ResponseText)
	}

	listRequestsResponse, listRequestsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/ai/triage/requests?request_kind=finding_summary",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listRequestsResponse.Body.Close()
	var listRequestsPayload struct {
		Items []models.AITriageRequest `json:"items"`
	}
	decodeJSONResponse(t, listRequestsBody, &listRequestsPayload)
	if len(listRequestsPayload.Items) != 1 {
		t.Fatalf("expected 1 ai triage request, got %d", len(listRequestsPayload.Items))
	}
}
