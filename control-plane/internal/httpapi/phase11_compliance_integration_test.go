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

func TestPhase11OWASPMappingSyncFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase11_owasp_sync_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase11-owasp-sync-secret"
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
	now := time.Date(2026, time.March, 6, 12, 0, 0, 0, time.UTC)

	findingID := fmt.Sprintf("finding-owasp-sync-%d", time.Now().UTC().UnixNano())
	taskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "api",
		Target:     "https://api.example.com",
		Profile:    "default",
		Tools:      []string{"semgrep"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase11-owasp-worker",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "phase11-owasp-host",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "semgrep",
				SupportedTargetKinds: []string{"api"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModePassive},
				Labels:               []string{"phase11"},
			},
		},
	})

	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:     taskID,
		WorkerID:   "phase11-owasp-worker",
		FinalState: "completed",
		ReportedFindings: []models.CanonicalFinding{
			{
				FindingID:     findingID,
				Category:      "api_bola",
				Title:         "Broken object level authorization",
				Description:   "IDOR issue in API endpoint /v1/users/{id}",
				Severity:      "high",
				Confidence:    "high",
				Status:        "open",
				FirstSeenAt:   now,
				LastSeenAt:    now,
				SchemaVersion: "1.0.0",
				Asset: models.CanonicalAssetInfo{
					AssetID:     "api.example.com",
					AssetType:   "api",
					AssetName:   "Public API",
					Environment: "production",
					Exposure:    "internet",
					ServiceName: "public-api",
					OwnerTeam:   "platform",
					ServiceTier: "tier1",
					OwnerHierarchy: []string{
						"engineering",
						"platform",
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("finalize owasp mapping finding: %v", err)
	}

	syncResponse, syncBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/compliance/owasp/sync",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"limit":      200,
			"frameworks": []string{"owasp_top10", "owasp_api_top10"},
		},
		http.StatusOK,
	)
	defer syncResponse.Body.Close()

	var syncResult models.OWASPMappingSyncResult
	decodeJSONResponse(t, syncBody, &syncResult)
	if syncResult.ProcessedFindings < 1 {
		t.Fatalf("expected processed_findings>=1, got %d", syncResult.ProcessedFindings)
	}
	if syncResult.CreatedMappings < 2 {
		t.Fatalf("expected at least 2 created mappings, got %d", syncResult.CreatedMappings)
	}
	if syncResult.FrameworkTotals["owasp_top10"] < 1 {
		t.Fatalf("expected owasp_top10 mapping count, got %#v", syncResult.FrameworkTotals)
	}
	if syncResult.FrameworkTotals["owasp_api_top10"] < 1 {
		t.Fatalf("expected owasp_api_top10 mapping count, got %#v", syncResult.FrameworkTotals)
	}

	top10Response, top10Body := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/compliance/mappings?framework=owasp_top10&source_id="+findingID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer top10Response.Body.Close()
	var top10Payload struct {
		Items []models.ComplianceControlMapping `json:"items"`
	}
	decodeJSONResponse(t, top10Body, &top10Payload)
	if len(top10Payload.Items) != 1 {
		t.Fatalf("expected 1 owasp_top10 mapping, got %d", len(top10Payload.Items))
	}
	if top10Payload.Items[0].ControlID != "A01-BROKEN-ACCESS-CONTROL" {
		t.Fatalf("expected A01 control id, got %s", top10Payload.Items[0].ControlID)
	}

	apiTop10Response, apiTop10Body := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/compliance/mappings?framework=owasp_api_top10&source_id="+findingID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer apiTop10Response.Body.Close()
	var apiTop10Payload struct {
		Items []models.ComplianceControlMapping `json:"items"`
	}
	decodeJSONResponse(t, apiTop10Body, &apiTop10Payload)
	if len(apiTop10Payload.Items) != 1 {
		t.Fatalf("expected 1 owasp_api_top10 mapping, got %d", len(apiTop10Payload.Items))
	}
	if apiTop10Payload.Items[0].ControlID != "API1-BROKEN-OBJECT-LEVEL-AUTHORIZATION" {
		t.Fatalf("expected API1 control id, got %s", apiTop10Payload.Items[0].ControlID)
	}
}

func TestPhase11SAMMMetricsFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase11_samm_metrics_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase11-samm-secret"
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

	for _, payload := range []map[string]any{
		{
			"source_kind":   "finding",
			"source_id":     "finding-samm-001",
			"finding_id":    "finding-samm-001",
			"framework":     "samm",
			"category":      "governance.strategy_and_metrics",
			"control_id":    "SM1.1",
			"control_title": "Define Security KPIs",
			"status":        "planned",
		},
		{
			"source_kind":   "finding",
			"source_id":     "finding-samm-002",
			"finding_id":    "finding-samm-002",
			"framework":     "samm",
			"category":      "governance.strategy_and_metrics",
			"control_id":    "SM2.2",
			"control_title": "Track Security KPIs",
			"status":        "verified",
		},
		{
			"source_kind":   "finding",
			"source_id":     "finding-samm-003",
			"finding_id":    "finding-samm-003",
			"framework":     "samm",
			"category":      "verification.security_testing",
			"control_id":    "ST2.1",
			"control_title": "Continuous Security Testing",
			"status":        "implemented",
		},
	} {
		response, _ := mustJSONRequest(
			t,
			client,
			http.MethodPost,
			testServer.URL+"/v1/compliance/mappings",
			cfg.BootstrapAdminToken,
			auth.WorkerSecretHeader,
			"",
			payload,
			http.StatusCreated,
		)
		_ = response.Body.Close()
	}

	metricsResponse, metricsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/compliance/samm/metrics",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer metricsResponse.Body.Close()

	var metrics models.SAMMMetrics
	decodeJSONResponse(t, metricsBody, &metrics)

	if metrics.TotalControls != 3 {
		t.Fatalf("expected total_controls=3, got %d", metrics.TotalControls)
	}
	if metrics.StatusTotals["planned"] != 1 {
		t.Fatalf("expected planned total=1, got %d", metrics.StatusTotals["planned"])
	}
	if metrics.StatusTotals["implemented"] != 1 {
		t.Fatalf("expected implemented total=1, got %d", metrics.StatusTotals["implemented"])
	}
	if metrics.StatusTotals["verified"] != 1 {
		t.Fatalf("expected verified total=1, got %d", metrics.StatusTotals["verified"])
	}
	if metrics.ConsideredControlSize != 3 {
		t.Fatalf("expected considered_control_size=3, got %d", metrics.ConsideredControlSize)
	}
	if metrics.OverallMaturityScore <= 0 {
		t.Fatalf("expected positive overall maturity score, got %f", metrics.OverallMaturityScore)
	}
	if len(metrics.Categories) != 2 {
		t.Fatalf("expected 2 samm categories, got %d", len(metrics.Categories))
	}

	var governanceFound bool
	for _, category := range metrics.Categories {
		if category.Category != "governance.strategy_and_metrics" {
			continue
		}
		governanceFound = true
		if category.TotalControls != 2 {
			t.Fatalf("expected governance category controls=2, got %d", category.TotalControls)
		}
		if category.StatusTotals["planned"] != 1 || category.StatusTotals["verified"] != 1 {
			t.Fatalf("unexpected governance status totals: %#v", category.StatusTotals)
		}
		if category.GapCount != 1 {
			t.Fatalf("expected governance gap_count=1, got %d", category.GapCount)
		}
	}
	if !governanceFound {
		t.Fatal("expected governance.strategy_and_metrics category in samm metrics")
	}
}
