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

func TestPhase11ComplianceMappingFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase11_compliance_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase11-compliance-secret"
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

	createMappingResponse, createMappingBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/compliance/mappings",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"source_kind":   "finding",
			"source_id":     "finding-runtime-replay-001",
			"finding_id":    "finding-runtime-replay-001",
			"framework":     "owasp_top10",
			"category":      "A01:2021",
			"control_id":    "A01-BROKEN-ACCESS-CONTROL",
			"control_title": "Broken Access Control",
			"status":        "identified",
			"evidence_ref":  "local://evidence/runtime/waf-block-001.json",
			"notes":         "mapped by phase11 control-mapping flow",
		},
		http.StatusCreated,
	)
	defer createMappingResponse.Body.Close()

	var mapping models.ComplianceControlMapping
	decodeJSONResponse(t, createMappingBody, &mapping)
	if strings.TrimSpace(mapping.ID) == "" {
		t.Fatal("expected compliance mapping id")
	}
	if mapping.Framework != "owasp_top10" {
		t.Fatalf("expected owasp_top10 framework, got %s", mapping.Framework)
	}

	updateMappingResponse, updateMappingBody := mustJSONRequest(
		t,
		client,
		http.MethodPut,
		testServer.URL+"/v1/compliance/mappings/"+mapping.ID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"status": "verified",
			"notes":  "verified by AppSec against runtime evidence and retest",
		},
		http.StatusOK,
	)
	defer updateMappingResponse.Body.Close()
	decodeJSONResponse(t, updateMappingBody, &mapping)
	if mapping.Status != "verified" {
		t.Fatalf("expected verified compliance status, got %s", mapping.Status)
	}

	listMappingResponse, listMappingBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/compliance/mappings?framework=owasp_top10&source_id=finding-runtime-replay-001",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listMappingResponse.Body.Close()
	var listMappingPayload struct {
		Items []models.ComplianceControlMapping `json:"items"`
	}
	decodeJSONResponse(t, listMappingBody, &listMappingPayload)
	if len(listMappingPayload.Items) != 1 {
		t.Fatalf("expected 1 compliance mapping, got %d", len(listMappingPayload.Items))
	}

	summaryResponse, summaryBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/compliance/summary",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer summaryResponse.Body.Close()
	var summary models.ComplianceSummary
	decodeJSONResponse(t, summaryBody, &summary)
	if summary.TotalMappings != 1 {
		t.Fatalf("expected total_mappings=1, got %d", summary.TotalMappings)
	}
	if summary.FrameworkTotals["owasp_top10"] != 1 {
		t.Fatalf("expected framework owasp_top10 total=1, got %d", summary.FrameworkTotals["owasp_top10"])
	}
	if summary.StatusTotals["verified"] != 1 {
		t.Fatalf("expected status verified total=1, got %d", summary.StatusTotals["verified"])
	}
}
