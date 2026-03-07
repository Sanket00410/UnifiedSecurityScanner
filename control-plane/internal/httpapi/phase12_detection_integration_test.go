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

	promoteResponse, promoteBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/detection/rulepacks/"+rulepack.ID+"/versions/"+version.ID+"/promote",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"phase":        "active",
			"target_scope": "tenant:all",
			"notes":        "phase12 promotion to active",
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
}
