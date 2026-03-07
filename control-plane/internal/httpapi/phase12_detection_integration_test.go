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

func TestPhase12DetectionRulepackLifecycleFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase12_detection_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase12-detection-secret"
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

	createRulepackResponse, createRulepackBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/detection/rulepacks",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"name":        "Semgrep Enterprise Core",
			"engine":      "semgrep",
			"status":      "draft",
			"description": "primary semgrep rules for code security coverage",
		},
		http.StatusCreated,
	)
	defer createRulepackResponse.Body.Close()

	var rulepack models.DetectionRulepack
	decodeJSONResponse(t, createRulepackBody, &rulepack)
	if strings.TrimSpace(rulepack.ID) == "" {
		t.Fatal("expected detection rulepack id")
	}

	createVersionResponse, createVersionBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/versions",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"version_tag":   "2026.03.07",
			"content_ref":   "s3://rulepacks/semgrep/2026.03.07.tar.zst",
			"checksum":      "sha256:phase12rulepackchecksum",
			"status":        "draft",
			"quality_score": 0.98,
		},
		http.StatusCreated,
	)
	defer createVersionResponse.Body.Close()

	var version models.DetectionRulepackVersion
	decodeJSONResponse(t, createVersionBody, &version)
	if strings.TrimSpace(version.ID) == "" {
		t.Fatal("expected detection rulepack version id")
	}

	createQualityRunResponse, createQualityRunBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/quality-runs",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"version_id":           version.ID,
			"benchmark_name":       "semgrep-regression-suite",
			"dataset_ref":          "s3://benchmarks/semgrep/regression-suite-v3.tar.zst",
			"run_status":           "passed",
			"quality_score":        0.96,
			"total_tests":          1200,
			"passed_tests":         1190,
			"failed_tests":         10,
			"false_positive_count": 3,
			"false_negative_count": 2,
			"regression_count":     0,
			"suppression_delta":    -4,
			"notes":                "phase12 benchmark run",
		},
		http.StatusCreated,
	)
	defer createQualityRunResponse.Body.Close()

	var qualityRun models.DetectionRulepackQualityRun
	decodeJSONResponse(t, createQualityRunBody, &qualityRun)
	if strings.TrimSpace(qualityRun.ID) == "" {
		t.Fatal("expected detection quality run id")
	}
	if qualityRun.RunStatus != "passed" {
		t.Fatalf("expected quality run status passed, got %s", qualityRun.RunStatus)
	}

	promoteResponse, promoteBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/versions/"+version.ID+"/promote",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"phase":             "active",
			"target_scope":      "tenant:all",
			"notes":             "phase12 promotion to active",
			"min_quality_score": 0.9,
		},
		http.StatusOK,
	)
	defer promoteResponse.Body.Close()

	var rollout models.DetectionRulepackRollout
	decodeJSONResponse(t, promoteBody, &rollout)
	if strings.TrimSpace(rollout.ID) == "" {
		t.Fatal("expected detection rollout id")
	}
	if rollout.Phase != "active" {
		t.Fatalf("expected rollout phase active, got %s", rollout.Phase)
	}

	getRulepackResponse, getRulepackBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer getRulepackResponse.Body.Close()
	decodeJSONResponse(t, getRulepackBody, &rulepack)
	if rulepack.CurrentVersion != version.VersionTag {
		t.Fatalf("expected current_version %s, got %s", version.VersionTag, rulepack.CurrentVersion)
	}

	listVersionsResponse, listVersionsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/versions",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listVersionsResponse.Body.Close()
	var listVersionsPayload struct {
		Items []models.DetectionRulepackVersion `json:"items"`
	}
	decodeJSONResponse(t, listVersionsBody, &listVersionsPayload)
	if len(listVersionsPayload.Items) != 1 {
		t.Fatalf("expected 1 detection rulepack version, got %d", len(listVersionsPayload.Items))
	}
	if listVersionsPayload.Items[0].Status != "active" {
		t.Fatalf("expected active version status, got %s", listVersionsPayload.Items[0].Status)
	}

	listRolloutsResponse, listRolloutsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/rollouts",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listRolloutsResponse.Body.Close()
	var listRolloutsPayload struct {
		Items []models.DetectionRulepackRollout `json:"items"`
	}
	decodeJSONResponse(t, listRolloutsBody, &listRolloutsPayload)
	if len(listRolloutsPayload.Items) != 1 {
		t.Fatalf("expected 1 detection rollout, got %d", len(listRolloutsPayload.Items))
	}

	listQualityRunsResponse, listQualityRunsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/quality-runs?version_id="+version.ID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listQualityRunsResponse.Body.Close()
	var listQualityRunsPayload struct {
		Items []models.DetectionRulepackQualityRun `json:"items"`
	}
	decodeJSONResponse(t, listQualityRunsBody, &listQualityRunsPayload)
	if len(listQualityRunsPayload.Items) != 1 {
		t.Fatalf("expected 1 detection quality run, got %d", len(listQualityRunsPayload.Items))
	}
	if listQualityRunsPayload.Items[0].VersionID != version.ID {
		t.Fatalf("expected quality run version id %s, got %s", version.ID, listQualityRunsPayload.Items[0].VersionID)
	}
}

func TestPhase12DetectionPromotionRequiresQualityGate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase12_detection_gate_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase12-detection-gate-secret"
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

	createRulepackResponse, createRulepackBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/detection/rulepacks",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"name":        "Semgrep Candidate Pack",
			"engine":      "semgrep",
			"status":      "draft",
			"description": "candidate quality-gated pack",
		},
		http.StatusCreated,
	)
	defer createRulepackResponse.Body.Close()
	var rulepack models.DetectionRulepack
	decodeJSONResponse(t, createRulepackBody, &rulepack)

	createVersionResponse, createVersionBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/versions",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"version_tag":   "2026.03.08-candidate",
			"content_ref":   "s3://rulepacks/semgrep/2026.03.08-candidate.tar.zst",
			"checksum":      "sha256:phase12candidatechecksum",
			"status":        "draft",
			"quality_score": 0.2,
		},
		http.StatusCreated,
	)
	defer createVersionResponse.Body.Close()
	var version models.DetectionRulepackVersion
	decodeJSONResponse(t, createVersionBody, &version)

	blockedResponse, blockedBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/versions/"+version.ID+"/promote",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"phase":             "active",
			"target_scope":      "tenant:all",
			"notes":             "should fail without quality run",
			"min_quality_score": 0.9,
		},
		http.StatusConflict,
	)
	defer blockedResponse.Body.Close()
	var blockedPayload map[string]any
	decodeJSONResponse(t, blockedBody, &blockedPayload)
	if blockedPayload["code"] != "detection_quality_gate_failed" {
		t.Fatalf("expected detection_quality_gate_failed code, got %#v", blockedPayload["code"])
	}

	createQualityRunResponse, _ := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/quality-runs",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"version_id":           version.ID,
			"benchmark_name":       "semgrep-regression-suite",
			"dataset_ref":          "s3://benchmarks/semgrep/regression-suite-v3.tar.zst",
			"run_status":           "passed",
			"quality_score":        0.94,
			"total_tests":          1400,
			"passed_tests":         1388,
			"failed_tests":         12,
			"false_positive_count": 4,
			"false_negative_count": 3,
			"regression_count":     0,
			"suppression_delta":    -2,
			"notes":                "quality gate pass run",
		},
		http.StatusCreated,
	)
	defer createQualityRunResponse.Body.Close()

	promoteResponse, promoteBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/versions/"+version.ID+"/promote",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"phase":             "active",
			"target_scope":      "tenant:all",
			"notes":             "should pass with quality run",
			"min_quality_score": 0.9,
		},
		http.StatusOK,
	)
	defer promoteResponse.Body.Close()
	var rollout models.DetectionRulepackRollout
	decodeJSONResponse(t, promoteBody, &rollout)
	if rollout.Phase != "active" {
		t.Fatalf("expected active rollout after quality gate, got %s", rollout.Phase)
	}
}
