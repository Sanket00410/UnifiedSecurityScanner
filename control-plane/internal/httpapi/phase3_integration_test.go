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

type phase3StubStore struct {
	*stubAPIStore
	findings []models.CanonicalFinding
}

func (s *phase3StubStore) ListFindingsForTenant(context.Context, string, int) ([]models.CanonicalFinding, error) {
	return s.findings, nil
}
