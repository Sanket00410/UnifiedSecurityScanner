package httpapi

import (
	"context"
	"encoding/json"
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

func TestPhase3RiskFlowPrioritizesFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase3_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase3-integration-secret"

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

	exploitTaskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "domain",
		Target:     "prod.example.com",
		Profile:    "default",
		Tools:      []string{"metasploit"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase3-worker-exploit",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "phase3-host-exploit",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "metasploit",
				SupportedTargetKinds: []string{"domain"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModeRestrictedExploit},
				Labels:               []string{"phase3"},
			},
		},
	})

	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:     exploitTaskID,
		WorkerID:   "phase3-worker-exploit",
		FinalState: "completed",
		ReportedFindings: []models.CanonicalFinding{
			{
				FindingID:     exploitTaskID + "-finding",
				Category:      "exploit_confirmed",
				Title:         "Confirmed exploitable condition",
				Severity:      "critical",
				Confidence:    "high",
				Status:        "open",
				FirstSeenAt:   now,
				LastSeenAt:    now,
				SchemaVersion: "1.0.0",
			},
		},
	}); err != nil {
		t.Fatalf("finalize exploit finding: %v", err)
	}

	sastTaskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "repository",
		Target:     "C:/repo",
		Profile:    "default",
		Tools:      []string{"semgrep"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase3-worker-sast",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "phase3-host-sast",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "semgrep",
				SupportedTargetKinds: []string{"repository"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModePassive},
				Labels:               []string{"phase3"},
			},
		},
	})

	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:     sastTaskID,
		WorkerID:   "phase3-worker-sast",
		FinalState: "completed",
		ReportedFindings: []models.CanonicalFinding{
			{
				FindingID:     sastTaskID + "-finding",
				Category:      "sast_rule_match",
				Title:         "Potential unsafe sink",
				Severity:      "high",
				Confidence:    "high",
				Status:        "open",
				FirstSeenAt:   now,
				LastSeenAt:    now,
				SchemaVersion: "1.0.0",
			},
		},
	}); err != nil {
		t.Fatalf("finalize sast finding: %v", err)
	}

	response, body := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/findings", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer response.Body.Close()

	var payload struct {
		Items []models.CanonicalFinding `json:"items"`
	}
	decodeJSONResponse(t, body, &payload)

	if len(payload.Items) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(payload.Items))
	}

	first := payload.Items[0]
	second := payload.Items[1]

	if first.Category != "exploit_confirmed" {
		t.Fatalf("expected highest-priority finding first, got %s", first.Category)
	}
	if first.Risk.Priority != "p0" {
		t.Fatalf("expected first finding priority p0, got %s", first.Risk.Priority)
	}
	if first.Asset.Exposure != "internet" {
		t.Fatalf("expected first finding exposure internet, got %s", first.Asset.Exposure)
	}
	if first.Risk.SLAClass != "24h" {
		t.Fatalf("expected first finding sla 24h, got %s", first.Risk.SLAClass)
	}
	if first.Risk.SLADueAt == nil {
		t.Fatal("expected first finding to include an sla due date")
	}

	if second.Category != "sast_rule_match" {
		t.Fatalf("expected lower-priority finding second, got %s", second.Category)
	}
	if second.Risk.Priority != "p3" {
		t.Fatalf("expected second finding priority p3, got %s", second.Risk.Priority)
	}
	if second.Asset.Exposure != "internal" {
		t.Fatalf("expected second finding exposure internal, got %s", second.Asset.Exposure)
	}
	if second.Risk.OverallScore >= first.Risk.OverallScore {
		t.Fatalf("expected first finding score %.2f to be greater than second %.2f", first.Risk.OverallScore, second.Risk.OverallScore)
	}
}

func createAssignedTask(
	t *testing.T,
	client *http.Client,
	baseURL string,
	token string,
	workerSecret string,
	jobRequest models.CreateScanJobRequest,
	workerRequest models.WorkerRegistrationRequest,
) string {
	t.Helper()

	response, body := mustJSONRequest(t, client, http.MethodPost, baseURL+"/v1/scan-jobs", token, auth.WorkerSecretHeader, "", jobRequest, http.StatusCreated)
	defer response.Body.Close()

	var job models.ScanJob
	decodeJSONResponse(t, body, &job)
	if job.ID == "" {
		t.Fatal("expected scan job id")
	}

	registrationResponse, registrationBody := mustJSONRequest(t, client, http.MethodPost, baseURL+"/v1/workers/register", "", auth.WorkerSecretHeader, workerSecret, workerRequest, http.StatusOK)
	defer registrationResponse.Body.Close()

	var registration models.WorkerRegistrationResponse
	decodeJSONResponse(t, registrationBody, &registration)
	if !registration.Accepted {
		t.Fatal("expected worker registration to be accepted")
	}

	heartbeatResponse, heartbeatBody := mustJSONRequest(t, client, http.MethodPost, baseURL+"/v1/workers/heartbeat", "", auth.WorkerSecretHeader, workerSecret, models.HeartbeatRequest{
		WorkerID:      workerRequest.WorkerID,
		LeaseID:       registration.LeaseID,
		TimestampUnix: time.Now().UTC().Unix(),
		Metrics: map[string]string{
			"phase": "3",
		},
	}, http.StatusOK)
	defer heartbeatResponse.Body.Close()

	var heartbeat models.HeartbeatResponse
	decodeJSONResponse(t, heartbeatBody, &heartbeat)
	if len(heartbeat.Assignments) != 1 {
		t.Fatalf("expected 1 assignment, got %d", len(heartbeat.Assignments))
	}

	return heartbeat.Assignments[0].JobID
}

func TestFindingsAPIIncludesRiskFieldsInResponseShape(t *testing.T) {
	t.Parallel()

	store := &stubAPIStore{
		authenticated: true,
		authPrincipal: models.AuthPrincipal{
			UserID:           "user-1",
			OrganizationID:   "org-1",
			OrganizationSlug: "org",
			OrganizationName: "Org",
			Email:            "viewer@example.com",
			DisplayName:      "Viewer",
			Role:             "viewer",
			AuthProvider:     "local",
			Scopes:           []string{"*"},
		},
	}
	storeFindings := []models.CanonicalFinding{
		{
			SchemaVersion: "1.0.0",
			FindingID:     "finding-1",
			TenantID:      "org-1",
			Category:      "exploit_confirmed",
			Title:         "Confirmed exploitable condition",
			Severity:      "critical",
			Confidence:    "high",
			Status:        "open",
			FirstSeenAt:   time.Now().UTC(),
			LastSeenAt:    time.Now().UTC(),
			Asset: models.CanonicalAssetInfo{
				AssetID:     "prod.example.com",
				AssetType:   "domain",
				AssetName:   "prod.example.com",
				Environment: "production",
				Exposure:    "internet",
			},
			Risk: models.CanonicalRisk{
				Priority:         "p0",
				OverallScore:     100,
				BusinessImpact:   10,
				Exploitability:   10,
				Reachability:     10,
				Exposure:         9,
				AssetCriticality: 10,
				PolicyImpact:     10,
				SLAClass:         "24h",
			},
		},
	}

	server := New(config.Load(), &phase3StubStore{stubAPIStore: store, findings: storeFindings})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/findings", nil)
	request.Header.Set("Authorization", "Bearer viewer-token")

	server.httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode findings response: %v", err)
	}

	items, ok := payload["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("unexpected findings payload: %#v", payload["items"])
	}
	firstItem, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected first item payload: %#v", items[0])
	}
	riskPayload, ok := firstItem["risk"].(map[string]any)
	if !ok {
		t.Fatalf("expected risk object in response, got %#v", firstItem["risk"])
	}
	if riskPayload["sla_class"] != "24h" {
		t.Fatalf("expected sla_class in response, got %#v", riskPayload["sla_class"])
	}
}

func TestPhase3AssetContextAndDedupFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase3_asset_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase3-asset-secret"

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

	profileResponse, profileBody := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/assets/public.example.com", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"asset_type":  "domain",
		"asset_name":  "public.example.com",
		"environment": "production",
		"exposure":    "internet",
		"criticality": 10,
		"owner_team":  "edge-security",
		"tags":        []string{"internet-facing", "customer"},
	}, http.StatusOK)
	defer profileResponse.Body.Close()

	var profile models.AssetProfile
	decodeJSONResponse(t, profileBody, &profile)
	if profile.OwnerTeam != "edge-security" {
		t.Fatalf("expected owner team in asset profile, got %s", profile.OwnerTeam)
	}

	controlResponse, controlBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/assets/public.example.com/controls", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":          "Web Application Firewall",
		"control_type":  "waf",
		"scope_layer":   "dast",
		"effectiveness": 8,
		"enabled":       true,
		"notes":         "Blocks common injection payloads",
	}, http.StatusCreated)
	defer controlResponse.Body.Close()

	var control models.CompensatingControl
	decodeJSONResponse(t, controlBody, &control)
	if !control.Enabled {
		t.Fatal("expected compensating control to be enabled")
	}

	firstTaskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "domain",
		Target:     "public.example.com",
		Profile:    "default",
		Tools:      []string{"zap"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase3-worker-zap-1",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "phase3-host-zap-1",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "zap",
				SupportedTargetKinds: []string{"domain"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModeActiveValidation},
				Labels:               []string{"phase3"},
			},
		},
	})

	firstFinding := models.CanonicalFinding{
		SchemaVersion: "1.0.0",
		Category:      "web_application_exposure",
		Title:         "SQL injection",
		Severity:      "high",
		Confidence:    "high",
		Status:        "open",
		FirstSeenAt:   now,
		LastSeenAt:    now,
		Locations: []models.CanonicalLocation{
			{Kind: "endpoint", Endpoint: "https://public.example.com/login"},
		},
	}
	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:           firstTaskID,
		WorkerID:         "phase3-worker-zap-1",
		FinalState:       "completed",
		ReportedFindings: []models.CanonicalFinding{firstFinding},
	}); err != nil {
		t.Fatalf("finalize first finding: %v", err)
	}

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
		t.Fatalf("mark finding resolved: %v", err)
	}

	secondTaskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "domain",
		Target:     "public.example.com",
		Profile:    "default",
		Tools:      []string{"zap"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase3-worker-zap-2",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "phase3-host-zap-2",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "zap",
				SupportedTargetKinds: []string{"domain"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModeActiveValidation},
				Labels:               []string{"phase3"},
			},
		},
	})

	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:           secondTaskID,
		WorkerID:         "phase3-worker-zap-2",
		FinalState:       "completed",
		ReportedFindings: []models.CanonicalFinding{firstFinding},
	}); err != nil {
		t.Fatalf("finalize second finding: %v", err)
	}

	findingsResponse, findingsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/findings", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer findingsResponse.Body.Close()

	var findingsPayload struct {
		Items []models.CanonicalFinding `json:"items"`
	}
	decodeJSONResponse(t, findingsBody, &findingsPayload)

	if len(findingsPayload.Items) != 1 {
		t.Fatalf("expected deduplicated single finding, got %d", len(findingsPayload.Items))
	}

	finding := findingsPayload.Items[0]
	if finding.OccurrenceCount != 2 {
		t.Fatalf("expected occurrence_count 2, got %d", finding.OccurrenceCount)
	}
	if finding.ReopenedCount != 1 {
		t.Fatalf("expected reopened_count 1, got %d", finding.ReopenedCount)
	}
	if finding.Asset.OwnerTeam != "edge-security" {
		t.Fatalf("expected owner team from asset profile, got %s", finding.Asset.OwnerTeam)
	}
	if finding.Risk.CompensatingControlReduction <= 0 {
		t.Fatalf("expected compensating control reduction, got %.2f", finding.Risk.CompensatingControlReduction)
	}

	assetsResponse, assetsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/assets", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer assetsResponse.Body.Close()

	var assetsPayload struct {
		Items []models.AssetSummary `json:"items"`
	}
	decodeJSONResponse(t, assetsBody, &assetsPayload)
	if len(assetsPayload.Items) != 1 {
		t.Fatalf("expected 1 asset summary, got %d", len(assetsPayload.Items))
	}
	if assetsPayload.Items[0].CompensatingControlCount != 1 {
		t.Fatalf("expected compensating control count 1, got %d", assetsPayload.Items[0].CompensatingControlCount)
	}
	if assetsPayload.Items[0].Criticality != 10 {
		t.Fatalf("expected criticality 10, got %.2f", assetsPayload.Items[0].Criticality)
	}
}

func TestPhase3WaiversTrendsAndAssetSyncFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase3_waiver_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase3-waiver-secret"

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

	syncResponse, syncBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/assets/sync", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"source": "cmdb",
		"assets": []map[string]any{
			{
				"asset_id":                  "api.internal.service",
				"asset_type":                "api",
				"asset_name":                "Payments API",
				"environment":               "production",
				"exposure":                  "internal",
				"criticality":               8,
				"owner_team":                "platform-security",
				"owner_hierarchy":           []string{"security", "payments"},
				"service_name":              "payments-api",
				"service_tier":              "tier-1",
				"service_criticality_class": "tier0",
				"external_reference":        "cmdb-42",
				"tags":                      []string{"cmdb", "payments"},
			},
		},
	}, http.StatusOK)
	defer syncResponse.Body.Close()

	var syncPayload models.SyncAssetProfilesResult
	decodeJSONResponse(t, syncBody, &syncPayload)
	if syncPayload.ImportedCount != 1 {
		t.Fatalf("expected 1 synced asset, got %d", syncPayload.ImportedCount)
	}

	assetsBeforeResponse, assetsBeforeBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/assets", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer assetsBeforeResponse.Body.Close()

	var assetsBeforePayload struct {
		Items []models.AssetSummary `json:"items"`
	}
	decodeJSONResponse(t, assetsBeforeBody, &assetsBeforePayload)
	if len(assetsBeforePayload.Items) != 1 {
		t.Fatalf("expected synced asset to appear before scans, got %d items", len(assetsBeforePayload.Items))
	}
	if assetsBeforePayload.Items[0].ServiceCriticalityClass != "tier0" {
		t.Fatalf("expected service criticality class tier0, got %s", assetsBeforePayload.Items[0].ServiceCriticalityClass)
	}
	if len(assetsBeforePayload.Items[0].OwnerHierarchy) != 2 {
		t.Fatalf("expected owner hierarchy length 2, got %d", len(assetsBeforePayload.Items[0].OwnerHierarchy))
	}
	if assetsBeforePayload.Items[0].ExternalSource != "cmdb" {
		t.Fatalf("expected external source cmdb, got %s", assetsBeforePayload.Items[0].ExternalSource)
	}
	if assetsBeforePayload.Items[0].LastSyncedAt == nil {
		t.Fatal("expected last_synced_at to be set")
	}

	policyResponse, policyBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/policies", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":    "Require approval for ZAP",
		"scope":   "tenant",
		"mode":    "enforce",
		"enabled": true,
		"rules": []map[string]any{
			{
				"effect": "require_approval",
				"field":  "tool",
				"match":  "exact",
				"values": []string{"zap"},
			},
		},
	}, http.StatusCreated)
	defer policyResponse.Body.Close()

	var policy models.Policy
	decodeJSONResponse(t, policyBody, &policy)
	if policy.ID == "" {
		t.Fatal("expected policy id")
	}

	jobResponse, jobBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/scan-jobs", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"target_kind": "api",
		"target":      "api.internal.service",
		"profile":     "default",
		"tools":       []string{"zap"},
	}, http.StatusCreated)
	defer jobResponse.Body.Close()

	var job models.ScanJob
	decodeJSONResponse(t, jobBody, &job)
	if job.ApprovalMode != "manual-approval" {
		t.Fatalf("expected manual-approval mode, got %s", job.ApprovalMode)
	}

	approvalsResponse, approvalsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/policy-approvals", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer approvalsResponse.Body.Close()

	var approvalsPayload struct {
		Items []models.PolicyApproval `json:"items"`
	}
	decodeJSONResponse(t, approvalsBody, &approvalsPayload)
	if len(approvalsPayload.Items) != 1 {
		t.Fatalf("expected 1 policy approval, got %d", len(approvalsPayload.Items))
	}
	approvalID := approvalsPayload.Items[0].ID

	approveResponse, approveBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/policy-approvals/"+approvalID+"/approve", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"reason": "risk board approved limited validation",
	}, http.StatusOK)
	defer approveResponse.Body.Close()

	var approved models.PolicyApproval
	decodeJSONResponse(t, approveBody, &approved)
	if approved.Status != "approved" {
		t.Fatalf("expected approved policy approval, got %s", approved.Status)
	}

	registrationRequest := models.WorkerRegistrationRequest{
		WorkerID:        "phase3-worker-zap-waiver",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "phase3-host-zap-waiver",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "zap",
				SupportedTargetKinds: []string{"api"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModeActiveValidation},
				Labels:               []string{"phase3"},
			},
		},
	}
	registrationResponse, registrationBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/workers/register", "", auth.WorkerSecretHeader, cfg.WorkerSharedSecret, registrationRequest, http.StatusOK)
	defer registrationResponse.Body.Close()

	var registration models.WorkerRegistrationResponse
	decodeJSONResponse(t, registrationBody, &registration)
	heartbeat := mustHeartbeat(t, client, testServer.URL, cfg.WorkerSharedSecret, registrationRequest.WorkerID, registration.LeaseID)
	if len(heartbeat.Assignments) != 1 {
		t.Fatalf("expected 1 assignment after approval, got %d", len(heartbeat.Assignments))
	}
	taskID := heartbeat.Assignments[0].JobID

	reportedFinding := models.CanonicalFinding{
		SchemaVersion: "1.0.0",
		Category:      "web_application_exposure",
		Title:         "Authenticated SQL injection",
		Severity:      "high",
		Confidence:    "high",
		Status:        "open",
		FirstSeenAt:   now.Add(-10 * 24 * time.Hour),
		LastSeenAt:    now,
		Locations: []models.CanonicalLocation{
			{Kind: "endpoint", Endpoint: "https://api.internal.service/v1/payments"},
		},
	}
	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:           taskID,
		WorkerID:         registrationRequest.WorkerID,
		FinalState:       "completed",
		ReportedFindings: []models.CanonicalFinding{reportedFinding},
	}); err != nil {
		t.Fatalf("finalize task with waiver test finding: %v", err)
	}

	findingsBeforeResponse, findingsBeforeBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/findings", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer findingsBeforeResponse.Body.Close()

	var findingsBeforePayload struct {
		Items []models.CanonicalFinding `json:"items"`
	}
	decodeJSONResponse(t, findingsBeforeBody, &findingsBeforePayload)
	if len(findingsBeforePayload.Items) != 1 {
		t.Fatalf("expected 1 finding before waiver, got %d", len(findingsBeforePayload.Items))
	}
	findingBefore := findingsBeforePayload.Items[0]
	if findingBefore.Asset.ServiceName != "payments-api" {
		t.Fatalf("expected synced service name on finding, got %s", findingBefore.Asset.ServiceName)
	}

	remediationResponse, remediationBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/remediations", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"finding_id": findingBefore.FindingID,
		"title":      "Accepted risk for limited payment endpoint",
		"status":     "accepted_risk",
		"owner":      "risk-board",
		"notes":      "Temporary compensating controls in place",
	}, http.StatusCreated)
	defer remediationResponse.Body.Close()

	var remediation models.RemediationAction
	decodeJSONResponse(t, remediationBody, &remediation)
	if remediation.ID == "" {
		t.Fatal("expected remediation id")
	}

	expiresAt := now.Add(30 * 24 * time.Hour)
	waiverResponse, waiverBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/findings/"+findingBefore.FindingID+"/waivers", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"remediation_id":     remediation.ID,
		"policy_approval_id": approvalID,
		"reason":             "accepted risk approved by policy gate",
		"reduction":          18,
		"expires_at":         expiresAt,
	}, http.StatusCreated)
	defer waiverResponse.Body.Close()

	var waiver models.FindingWaiver
	decodeJSONResponse(t, waiverBody, &waiver)
	if waiver.Status != "approved" {
		t.Fatalf("expected approved waiver, got %s", waiver.Status)
	}

	findingsAfterResponse, findingsAfterBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/findings", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer findingsAfterResponse.Body.Close()

	var findingsAfterPayload struct {
		Items []models.CanonicalFinding `json:"items"`
	}
	decodeJSONResponse(t, findingsAfterBody, &findingsAfterPayload)
	if len(findingsAfterPayload.Items) != 1 {
		t.Fatalf("expected 1 finding after waiver, got %d", len(findingsAfterPayload.Items))
	}
	findingAfter := findingsAfterPayload.Items[0]
	if findingAfter.Risk.WaiverReduction != 18 {
		t.Fatalf("expected waiver reduction 18, got %.2f", findingAfter.Risk.WaiverReduction)
	}
	if findingAfter.Risk.OverallScore >= findingBefore.Risk.OverallScore {
		t.Fatalf("expected waiver to reduce score below %.2f, got %.2f", findingBefore.Risk.OverallScore, findingAfter.Risk.OverallScore)
	}
	if findingAfter.Risk.AgeDays < 10 {
		t.Fatalf("expected aged finding of at least 10 days, got %d", findingAfter.Risk.AgeDays)
	}
	if findingAfter.Risk.AgingBucket != "7-30d" {
		t.Fatalf("expected aging bucket 7-30d, got %s", findingAfter.Risk.AgingBucket)
	}

	waiversResponse, waiversBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/findings/"+findingAfter.FindingID+"/waivers", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer waiversResponse.Body.Close()

	var waiversPayload struct {
		Items []models.FindingWaiver `json:"items"`
	}
	decodeJSONResponse(t, waiversBody, &waiversPayload)
	if len(waiversPayload.Items) != 1 {
		t.Fatalf("expected 1 waiver item, got %d", len(waiversPayload.Items))
	}
	if waiversPayload.Items[0].Status != "approved" {
		t.Fatalf("expected approved waiver from list, got %s", waiversPayload.Items[0].Status)
	}

	riskSummaryResponse, riskSummaryBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/risk/summary", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer riskSummaryResponse.Body.Close()

	var riskSummary models.RiskSummary
	decodeJSONResponse(t, riskSummaryBody, &riskSummary)
	if riskSummary.TotalFindings != 1 {
		t.Fatalf("expected total_findings 1, got %d", riskSummary.TotalFindings)
	}
	if riskSummary.Observations7d != 1 {
		t.Fatalf("expected observations_7d 1, got %d", riskSummary.Observations7d)
	}
	if riskSummary.NewFindings7d != 0 {
		t.Fatalf("expected new_findings_7d 0 for older finding, got %d", riskSummary.NewFindings7d)
	}
	if riskSummary.AgingBuckets["7-30d"] != 1 {
		t.Fatalf("expected 7-30d aging bucket count 1, got %d", riskSummary.AgingBuckets["7-30d"])
	}
	if riskSummary.PriorityCounts[findingAfter.Risk.Priority] != 1 {
		t.Fatalf("expected priority bucket %s count 1, got %d", findingAfter.Risk.Priority, riskSummary.PriorityCounts[findingAfter.Risk.Priority])
	}
}

type phase3StubStore struct {
	*stubAPIStore
	findings []models.CanonicalFinding
}

func (s *phase3StubStore) ListFindingsForTenant(context.Context, string, int) ([]models.CanonicalFinding, error) {
	return s.findings, nil
}
