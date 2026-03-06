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

func TestPhase6WebTargetPrepFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase6_web_prep_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase6-web-prep-secret"
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

	createTargetResponse, createTargetBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/web-targets", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":                  "Customer Portal",
		"target_type":           "webapp",
		"base_url":              "https://app.example.com",
		"in_scope_patterns":     []string{"app.example.com/app/*", "app.example.com/api/*"},
		"out_of_scope_patterns": []string{"app.example.com/logout"},
		"labels": map[string]any{
			"service": "customer-portal",
		},
	}, http.StatusCreated)
	defer createTargetResponse.Body.Close()

	var createdTarget models.WebTarget
	decodeJSONResponse(t, createTargetBody, &createdTarget)
	if strings.TrimSpace(createdTarget.ID) == "" {
		t.Fatal("expected created web target id")
	}
	if createdTarget.BaseURL != "https://app.example.com" {
		t.Fatalf("unexpected target base url: %s", createdTarget.BaseURL)
	}

	createProfileResponse, createProfileBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/web-auth-profiles", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":                   "Portal Auth",
		"auth_type":              "form",
		"login_url":              "https://app.example.com/login",
		"username_secret_ref":    "secret://web/portal/username",
		"password_secret_ref":    "secret://web/portal/password",
		"csrf_mode":              "auto",
		"token_refresh_strategy": "cookie_relogin",
		"session_bootstrap": map[string]any{
			"csrf_token_field": "_token",
		},
		"test_personas": []map[string]any{
			{"name": "appsec-admin", "role": "admin"},
		},
	}, http.StatusCreated)
	defer createProfileResponse.Body.Close()

	var createdProfile models.WebAuthProfile
	decodeJSONResponse(t, createProfileBody, &createdProfile)
	if strings.TrimSpace(createdProfile.ID) == "" {
		t.Fatal("expected created web auth profile id")
	}
	if createdProfile.AuthType != "form" {
		t.Fatalf("unexpected auth profile type: %s", createdProfile.AuthType)
	}

	crawlPolicyResponse, crawlPolicyBody := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/crawl-policy", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"auth_profile_id":           createdProfile.ID,
		"safe_mode":                 true,
		"max_depth":                 4,
		"max_requests":              1200,
		"request_budget_per_minute": 180,
		"allow_paths":               []string{"app.example.com/app/*", "app.example.com/api/*"},
		"deny_paths":                []string{"app.example.com/logout"},
		"seed_urls":                 []string{"https://app.example.com/app/home", "https://app.example.com/api/openapi.json"},
		"headers": map[string]any{
			"x-appsec-scan": "phase6",
		},
	}, http.StatusOK)
	defer crawlPolicyResponse.Body.Close()

	var crawlPolicy models.WebCrawlPolicy
	decodeJSONResponse(t, crawlPolicyBody, &crawlPolicy)
	if crawlPolicy.WebTargetID != createdTarget.ID {
		t.Fatalf("expected crawl policy target %s, got %s", createdTarget.ID, crawlPolicy.WebTargetID)
	}
	if !crawlPolicy.SafeMode {
		t.Fatal("expected safe_mode=true")
	}
	if crawlPolicy.AuthProfileID != createdProfile.ID {
		t.Fatalf("expected auth profile id %s, got %s", createdProfile.ID, crawlPolicy.AuthProfileID)
	}

	coverageResponse, coverageBody := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/coverage-baseline", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"expected_route_count":         85,
		"expected_api_operation_count": 36,
		"expected_auth_state_count":    5,
		"minimum_route_coverage":       82.5,
		"minimum_api_coverage":         75,
		"minimum_auth_coverage":        80,
		"notes":                        "Phase 6 onboarding baseline",
	}, http.StatusOK)
	defer coverageResponse.Body.Close()

	var coverage models.WebCoverageBaseline
	decodeJSONResponse(t, coverageBody, &coverage)
	if coverage.ExpectedRouteCount != 85 {
		t.Fatalf("expected route baseline 85, got %d", coverage.ExpectedRouteCount)
	}
	if coverage.MinimumAPICoverage != 75 {
		t.Fatalf("expected api coverage baseline 75, got %.1f", coverage.MinimumAPICoverage)
	}

	inScopeResponse, inScopeBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/scope/evaluate?url=https://app.example.com/app/dashboard",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer inScopeResponse.Body.Close()

	var inScope models.WebTargetScopeEvaluation
	decodeJSONResponse(t, inScopeBody, &inScope)
	if !inScope.InScope {
		t.Fatalf("expected in-scope url evaluation, got %#v", inScope)
	}

	outScopeResponse, outScopeBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/scope/evaluate?url=https://evil.example.com/admin",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer outScopeResponse.Body.Close()

	var outScope models.WebTargetScopeEvaluation
	decodeJSONResponse(t, outScopeBody, &outScope)
	if outScope.InScope {
		t.Fatalf("expected out-of-scope url evaluation, got %#v", outScope)
	}

	runResponse, runBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/run",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"profile": "runtime",
			"tools":   []string{"zap", "nuclei"},
		},
		http.StatusCreated,
	)
	defer runResponse.Body.Close()

	var runPayload struct {
		Target models.WebTarget `json:"target"`
		Job    models.ScanJob   `json:"job"`
	}
	decodeJSONResponse(t, runBody, &runPayload)
	if strings.TrimSpace(runPayload.Job.ID) == "" {
		t.Fatal("expected run endpoint to create scan job")
	}
	if runPayload.Target.ID != createdTarget.ID {
		t.Fatalf("expected run target id %s, got %s", createdTarget.ID, runPayload.Target.ID)
	}
	if runPayload.Job.Target != "https://app.example.com" {
		t.Fatalf("expected run job target https://app.example.com, got %s", runPayload.Job.Target)
	}

	listTargetsResponse, listTargetsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/web-targets", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer listTargetsResponse.Body.Close()

	var listedTargets struct {
		Items []models.WebTarget `json:"items"`
	}
	decodeJSONResponse(t, listTargetsBody, &listedTargets)
	if len(listedTargets.Items) != 1 {
		t.Fatalf("expected 1 web target, got %d", len(listedTargets.Items))
	}

	listProfilesResponse, listProfilesBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/web-auth-profiles", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer listProfilesResponse.Body.Close()

	var listedProfiles struct {
		Items []models.WebAuthProfile `json:"items"`
	}
	decodeJSONResponse(t, listProfilesBody, &listedProfiles)
	if len(listedProfiles.Items) != 1 {
		t.Fatalf("expected 1 web auth profile, got %d", len(listedProfiles.Items))
	}

	listJobsResponse, listJobsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/scan-jobs", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer listJobsResponse.Body.Close()

	var listedJobs struct {
		Items []models.ScanJob `json:"items"`
	}
	decodeJSONResponse(t, listJobsBody, &listedJobs)
	if len(listedJobs.Items) != 1 {
		t.Fatalf("expected 1 scan job from web target run, got %d", len(listedJobs.Items))
	}
}
