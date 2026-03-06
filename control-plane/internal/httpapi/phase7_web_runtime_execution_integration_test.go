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

func TestPhase7WebRuntimeRunGuardrailsAndAuthLabels(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase7_web_runtime_execution_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase7-web-runtime-exec-secret"
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
		"name":        "Phase7 Runtime Portal",
		"target_type": "webapp",
		"base_url":    "https://phase7.example.com",
	}, http.StatusCreated)
	defer createTargetResponse.Body.Close()

	var createdTarget models.WebTarget
	decodeJSONResponse(t, createTargetBody, &createdTarget)
	if strings.TrimSpace(createdTarget.ID) == "" {
		t.Fatal("expected created web target id")
	}

	createProfileResponse, createProfileBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/web-auth-profiles", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":                   "Phase7 Runtime Auth",
		"auth_type":              "form",
		"login_url":              "https://phase7.example.com/login",
		"username_secret_ref":    "secret://phase7/web/username",
		"password_secret_ref":    "secret://phase7/web/password",
		"csrf_mode":              "auto",
		"token_refresh_strategy": "cookie_relogin",
		"session_bootstrap": map[string]any{
			"csrf_token_field": "_token",
		},
		"test_personas": []map[string]any{
			{"name": "phase7-admin", "role": "admin"},
		},
		"enabled": false,
	}, http.StatusCreated)
	defer createProfileResponse.Body.Close()

	var createdProfile models.WebAuthProfile
	decodeJSONResponse(t, createProfileBody, &createdProfile)
	if strings.TrimSpace(createdProfile.ID) == "" {
		t.Fatal("expected created web auth profile id")
	}

	upsertPolicyResponse, upsertPolicyBody := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/crawl-policy", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"auth_profile_id":           createdProfile.ID,
		"safe_mode":                 true,
		"max_depth":                 3,
		"max_requests":              600,
		"request_budget_per_minute": 120,
	}, http.StatusOK)
	defer upsertPolicyResponse.Body.Close()
	var crawlPolicy models.WebCrawlPolicy
	decodeJSONResponse(t, upsertPolicyBody, &crawlPolicy)
	if !crawlPolicy.SafeMode {
		t.Fatal("expected safe_mode=true")
	}

	disabledRunResponse, disabledRunBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/run",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"profile": "runtime",
			"tools":   []string{"zap"},
		},
		http.StatusConflict,
	)
	defer disabledRunResponse.Body.Close()
	var disabledRunPayload map[string]any
	decodeJSONResponse(t, disabledRunBody, &disabledRunPayload)
	if disabledRunPayload["code"] != "web_auth_profile_disabled" {
		t.Fatalf("expected web_auth_profile_disabled, got %#v", disabledRunPayload["code"])
	}

	enableProfileResponse, enableProfileBody := mustJSONRequest(
		t,
		client,
		http.MethodPut,
		testServer.URL+"/v1/web-auth-profiles/"+createdProfile.ID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"name":                    createdProfile.Name,
			"auth_type":               createdProfile.AuthType,
			"login_url":               createdProfile.LoginURL,
			"username_secret_ref":     createdProfile.UsernameSecretRef,
			"password_secret_ref":     createdProfile.PasswordSecretRef,
			"bearer_token_secret_ref": createdProfile.BearerTokenSecretRef,
			"csrf_mode":               createdProfile.CSRFMode,
			"session_bootstrap":       createdProfile.SessionBootstrap,
			"test_personas":           createdProfile.TestPersonas,
			"token_refresh_strategy":  createdProfile.TokenRefreshStrategy,
			"enabled":                 true,
		},
		http.StatusOK,
	)
	defer enableProfileResponse.Body.Close()

	var enabledProfile models.WebAuthProfile
	decodeJSONResponse(t, enableProfileBody, &enabledProfile)
	if !enabledProfile.Enabled {
		t.Fatal("expected auth profile to be enabled")
	}

	disallowedToolResponse, disallowedToolBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/run",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"profile": "runtime",
			"tools":   []string{"metasploit"},
		},
		http.StatusBadRequest,
	)
	defer disallowedToolResponse.Body.Close()
	var disallowedToolPayload map[string]any
	decodeJSONResponse(t, disallowedToolBody, &disallowedToolPayload)
	if disallowedToolPayload["code"] != "web_runtime_tool_not_allowed" {
		t.Fatalf("expected web_runtime_tool_not_allowed, got %#v", disallowedToolPayload["code"])
	}

	updateSafeModeResponse, updateSafeModeBody := mustJSONRequest(
		t,
		client,
		http.MethodPut,
		testServer.URL+"/v1/web-targets/"+createdTarget.ID+"/crawl-policy",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"auth_profile_id":           createdProfile.ID,
			"safe_mode":                 false,
			"max_depth":                 3,
			"max_requests":              600,
			"request_budget_per_minute": 120,
		},
		http.StatusOK,
	)
	defer updateSafeModeResponse.Body.Close()
	decodeJSONResponse(t, updateSafeModeBody, &crawlPolicy)
	if crawlPolicy.SafeMode {
		t.Fatal("expected safe_mode=false")
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
			"tools":   []string{"zap"},
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
		t.Fatal("expected scan job id from web run")
	}

	workerRequest := models.WorkerRegistrationRequest{
		WorkerID:        "phase7-web-runtime-worker",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "linux",
		Hostname:        "phase7-web-runtime-host",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "zap",
				SupportedTargetKinds: []string{"url"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModeActiveValidation},
				Labels:               []string{"phase7"},
				LinuxPreferred:       true,
			},
		},
	}

	registerResponse, registerBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/workers/register",
		"",
		auth.WorkerSecretHeader,
		cfg.WorkerSharedSecret,
		workerRequest,
		http.StatusOK,
	)
	defer registerResponse.Body.Close()

	var registerPayload models.WorkerRegistrationResponse
	decodeJSONResponse(t, registerBody, &registerPayload)
	if !registerPayload.Accepted {
		t.Fatal("expected worker registration to be accepted")
	}

	heartbeatResponse, heartbeatBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/workers/heartbeat",
		"",
		auth.WorkerSecretHeader,
		cfg.WorkerSharedSecret,
		models.HeartbeatRequest{
			WorkerID:      workerRequest.WorkerID,
			LeaseID:       registerPayload.LeaseID,
			TimestampUnix: time.Now().UTC().Unix(),
			Metrics: map[string]string{
				"phase": "7",
			},
		},
		http.StatusOK,
	)
	defer heartbeatResponse.Body.Close()

	var heartbeatPayload models.HeartbeatResponse
	decodeJSONResponse(t, heartbeatBody, &heartbeatPayload)
	if len(heartbeatPayload.Assignments) != 1 {
		t.Fatalf("expected 1 assignment, got %d", len(heartbeatPayload.Assignments))
	}

	assignment := heartbeatPayload.Assignments[0]
	if assignment.AdapterID != "zap" {
		t.Fatalf("expected zap assignment, got %s", assignment.AdapterID)
	}
	if assignment.Labels["web_auth_profile_id"] != createdProfile.ID {
		t.Fatalf("expected web_auth_profile_id label %s, got %#v", createdProfile.ID, assignment.Labels["web_auth_profile_id"])
	}
	if assignment.Labels["web_auth_type"] != "form" {
		t.Fatalf("expected web_auth_type=form, got %#v", assignment.Labels["web_auth_type"])
	}
	if assignment.Labels["web_auth_login_url"] != "https://phase7.example.com/login" {
		t.Fatalf("expected web_auth_login_url label, got %#v", assignment.Labels["web_auth_login_url"])
	}
	if assignment.Labels["web_auth_username_secret_ref"] != "secret://phase7/web/username" {
		t.Fatalf("expected username secret ref label, got %#v", assignment.Labels["web_auth_username_secret_ref"])
	}
	if assignment.Labels["web_auth_password_secret_ref"] != "secret://phase7/web/password" {
		t.Fatalf("expected password secret ref label, got %#v", assignment.Labels["web_auth_password_secret_ref"])
	}
}
