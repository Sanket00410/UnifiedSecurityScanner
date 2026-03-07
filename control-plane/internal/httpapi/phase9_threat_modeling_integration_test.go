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

func TestPhase9ThreatModelingWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase9_threat_modeling_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase9-threat-modeling-secret"
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

	createReviewResponse, createReviewBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/design-reviews",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"title":               "Payments Service Threat Model",
			"service_name":        "payments-api",
			"service_id":          "asset-payments-api",
			"threat_template":     "stride-v1",
			"summary":             "initial architecture and abuse-case review",
			"diagram_ref":         "local://evidence/design/payments-dfd-v1.json",
			"data_classification": "restricted",
			"design_owner":        "payments-team@example.com",
			"reviewer":            "appsec@example.com",
		},
		http.StatusCreated,
	)
	defer createReviewResponse.Body.Close()

	var review models.DesignReview
	decodeJSONResponse(t, createReviewBody, &review)
	if strings.TrimSpace(review.ID) == "" {
		t.Fatal("expected design review id")
	}
	if review.Status != "draft" {
		t.Fatalf("expected draft design review status, got %s", review.Status)
	}

	submitResponse, submitBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/design-reviews/"+review.ID+"/submit",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{"reason": "ready for security review"},
		http.StatusOK,
	)
	defer submitResponse.Body.Close()
	decodeJSONResponse(t, submitBody, &review)
	if review.Status != "in_review" {
		t.Fatalf("expected in_review status, got %s", review.Status)
	}

	createThreatResponse, createThreatBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/design-reviews/"+review.ID+"/threats",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"category":              "spoofing",
			"title":                 "Token replay against payment callback endpoint",
			"description":           "attacker replays signed callback requests",
			"abuse_case":            "forged callback with stale token",
			"impact":                "unauthorized payment state transitions",
			"likelihood":            "medium",
			"severity":              "high",
			"status":                "open",
			"linked_asset_id":       "asset-payments-api",
			"linked_finding_id":     "finding-runtime-replay-001",
			"runtime_evidence_refs": []string{"local://evidence/runtime/callback-replay.har"},
			"mitigation":            "nonce + one-time token validation",
		},
		http.StatusCreated,
	)
	defer createThreatResponse.Body.Close()

	var threat models.DesignThreat
	decodeJSONResponse(t, createThreatBody, &threat)
	if strings.TrimSpace(threat.ID) == "" {
		t.Fatal("expected design threat id")
	}

	upsertFlowResponse, upsertFlowBody := mustJSONRequest(
		t,
		client,
		http.MethodPut,
		testServer.URL+"/v1/design-reviews/"+review.ID+"/data-flow",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"entities": []map[string]any{
				{"id": "ext-client", "name": "External Client", "kind": "external"},
				{"id": "payments-api", "name": "Payments API", "kind": "service"},
				{"id": "payments-db", "name": "Payments DB", "kind": "data_store"},
			},
			"flows": []map[string]any{
				{"from": "ext-client", "to": "payments-api", "protocol": "https", "auth": "jwt"},
				{"from": "payments-api", "to": "payments-db", "protocol": "postgres", "encrypted": true},
			},
			"trust_boundaries": []map[string]any{
				{"name": "internet", "between": []string{"ext-client", "payments-api"}},
			},
			"notes": "first-pass DFD for payment callback abuse-case analysis",
		},
		http.StatusOK,
	)
	defer upsertFlowResponse.Body.Close()

	var dataFlow models.DesignDataFlowModel
	decodeJSONResponse(t, upsertFlowBody, &dataFlow)
	if strings.TrimSpace(dataFlow.ID) == "" {
		t.Fatal("expected design data flow id")
	}
	if len(dataFlow.Entities) < 3 {
		t.Fatalf("expected at least 3 data flow entities, got %d", len(dataFlow.Entities))
	}

	createControlResponse, createControlBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/design-reviews/"+review.ID+"/control-mappings",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"threat_id":     threat.ID,
			"framework":     "asvs",
			"control_id":    "V3.2.2",
			"control_title": "Replay protection for high-risk operations",
			"status":        "planned",
			"evidence_ref":  "local://evidence/design/asvs-v3-2-2.md",
			"notes":         "mapped during phase9 review",
		},
		http.StatusCreated,
	)
	defer createControlResponse.Body.Close()

	var control models.DesignControlMapping
	decodeJSONResponse(t, createControlBody, &control)
	if strings.TrimSpace(control.ID) == "" {
		t.Fatal("expected design control mapping id")
	}

	approveResponse, approveBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/design-reviews/"+review.ID+"/approve",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{"reason": "accepted for implementation"},
		http.StatusOK,
	)
	defer approveResponse.Body.Close()
	decodeJSONResponse(t, approveBody, &review)
	if review.Status != "approved" {
		t.Fatalf("expected approved design review status, got %s", review.Status)
	}

	closeResponse, closeBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/design-reviews/"+review.ID+"/close",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{"reason": "review complete"},
		http.StatusOK,
	)
	defer closeResponse.Body.Close()
	decodeJSONResponse(t, closeBody, &review)
	if review.Status != "closed" {
		t.Fatalf("expected closed design review status, got %s", review.Status)
	}

	listReviewsResponse, listReviewsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/design-reviews?status=closed",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listReviewsResponse.Body.Close()
	var listReviewsPayload struct {
		Items []models.DesignReview `json:"items"`
	}
	decodeJSONResponse(t, listReviewsBody, &listReviewsPayload)
	if len(listReviewsPayload.Items) != 1 {
		t.Fatalf("expected 1 closed design review, got %d", len(listReviewsPayload.Items))
	}

	listThreatsResponse, listThreatsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/design-reviews/"+review.ID+"/threats",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listThreatsResponse.Body.Close()
	var listThreatsPayload struct {
		Items []models.DesignThreat `json:"items"`
	}
	decodeJSONResponse(t, listThreatsBody, &listThreatsPayload)
	if len(listThreatsPayload.Items) != 1 {
		t.Fatalf("expected 1 design threat, got %d", len(listThreatsPayload.Items))
	}

	listControlResponse, listControlBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/design-reviews/"+review.ID+"/control-mappings?framework=asvs",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listControlResponse.Body.Close()
	var listControlPayload struct {
		Items []models.DesignControlMapping `json:"items"`
	}
	decodeJSONResponse(t, listControlBody, &listControlPayload)
	if len(listControlPayload.Items) != 1 {
		t.Fatalf("expected 1 asvs design control mapping, got %d", len(listControlPayload.Items))
	}
}
