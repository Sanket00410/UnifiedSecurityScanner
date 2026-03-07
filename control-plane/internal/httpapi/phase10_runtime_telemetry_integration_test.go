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

func TestPhase10RuntimeTelemetryConnectorAndEventFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase10_runtime_telemetry_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase10-runtime-telemetry-secret"
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

	createConnectorResponse, createConnectorBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/runtime/telemetry/connectors",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"name":           "Primary WAF Log Connector",
			"connector_type": "waf",
			"status":         "active",
			"config": map[string]any{
				"provider":    "cloudflare",
				"dataset":     "http_requests",
				"poll_window": "5m",
			},
		},
		http.StatusCreated,
	)
	defer createConnectorResponse.Body.Close()

	var connector models.RuntimeTelemetryConnector
	decodeJSONResponse(t, createConnectorBody, &connector)
	if strings.TrimSpace(connector.ID) == "" {
		t.Fatal("expected runtime telemetry connector id")
	}
	if connector.ConnectorType != "waf" {
		t.Fatalf("expected waf connector type, got %s", connector.ConnectorType)
	}

	now := time.Now().UTC()
	updateConnectorResponse, updateConnectorBody := mustJSONRequest(
		t,
		client,
		http.MethodPut,
		testServer.URL+"/v1/runtime/telemetry/connectors/"+connector.ID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"status":       "active",
			"last_sync_at": now.Format(time.RFC3339Nano),
			"config": map[string]any{
				"provider":    "cloudflare",
				"dataset":     "http_requests",
				"poll_window": "1m",
			},
		},
		http.StatusOK,
	)
	defer updateConnectorResponse.Body.Close()
	decodeJSONResponse(t, updateConnectorBody, &connector)
	if connector.LastSyncAt == nil {
		t.Fatal("expected connector last_sync_at to be populated")
	}

	ingestEventResponse, ingestEventBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/runtime/telemetry/events",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"connector_id": connector.ID,
			"source_kind":  "waf",
			"source_ref":   "cloudflare:http_requests",
			"asset_id":     "asset-payments-api",
			"finding_id":   "finding-runtime-replay-001",
			"event_type":   "waf.blocked_request",
			"severity":     "medium",
			"payload": map[string]any{
				"path":        "/api/payments/callback",
				"action":      "block",
				"rule_id":     "waf-942100",
				"remote_addr": "203.0.113.10",
			},
			"evidence_refs": []string{"local://evidence/runtime/waf-block-001.json"},
		},
		http.StatusCreated,
	)
	defer ingestEventResponse.Body.Close()

	var event models.RuntimeTelemetryEvent
	decodeJSONResponse(t, ingestEventBody, &event)
	if strings.TrimSpace(event.ID) == "" {
		t.Fatal("expected runtime telemetry event id")
	}
	if event.EventType != "waf.blocked_request" {
		t.Fatalf("expected event_type waf.blocked_request, got %s", event.EventType)
	}

	listEventsResponse, listEventsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/runtime/telemetry/events?connector_id="+connector.ID+"&event_type=waf.blocked_request",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listEventsResponse.Body.Close()
	var listEventsPayload struct {
		Items []models.RuntimeTelemetryEvent `json:"items"`
	}
	decodeJSONResponse(t, listEventsBody, &listEventsPayload)
	if len(listEventsPayload.Items) != 1 {
		t.Fatalf("expected 1 runtime telemetry event, got %d", len(listEventsPayload.Items))
	}

	listConnectorsResponse, listConnectorsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/runtime/telemetry/connectors?connector_type=waf",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listConnectorsResponse.Body.Close()
	var listConnectorsPayload struct {
		Items []models.RuntimeTelemetryConnector `json:"items"`
	}
	decodeJSONResponse(t, listConnectorsBody, &listConnectorsPayload)
	if len(listConnectorsPayload.Items) != 1 {
		t.Fatalf("expected 1 waf runtime telemetry connector, got %d", len(listConnectorsPayload.Items))
	}
}

func TestPhase10RuntimeTelemetryFindingEnrichmentFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase10_runtime_enrichment_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase10-runtime-enrichment-secret"
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
	now := time.Date(2026, time.March, 5, 9, 0, 0, 0, time.UTC)

	liveFindingID := fmt.Sprintf("finding-runtime-live-%d", time.Now().UTC().UnixNano())
	liveTaskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "repository",
		Target:     "C:/repo/live-runtime-enrichment",
		Profile:    "default",
		Tools:      []string{"semgrep"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase10-worker-live",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "phase10-live-host",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "semgrep",
				SupportedTargetKinds: []string{"repository"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModePassive},
				Labels:               []string{"phase10"},
			},
		},
	})

	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:     liveTaskID,
		WorkerID:   "phase10-worker-live",
		FinalState: "completed",
		ReportedFindings: []models.CanonicalFinding{
			{
				FindingID:     liveFindingID,
				Category:      "sast_rule_match",
				Title:         "Potential unsafe sink",
				Severity:      "medium",
				Confidence:    "low",
				Status:        "open",
				FirstSeenAt:   now,
				LastSeenAt:    now,
				SchemaVersion: "1.0.0",
			},
		},
	}); err != nil {
		t.Fatalf("finalize live finding: %v", err)
	}

	_, _ = mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/runtime/telemetry/events",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"source_kind":   "waf",
			"source_ref":    "cloudflare:http_requests",
			"asset_id":      "asset-live-runtime",
			"finding_id":    liveFindingID,
			"event_type":    "waf.blocked_request",
			"severity":      "high",
			"evidence_refs": []string{"local://evidence/runtime/live-waf-block.json"},
		},
		http.StatusCreated,
	)

	liveListResponse, liveListBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/runtime/telemetry/enrichments?finding_id="+liveFindingID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer liveListResponse.Body.Close()

	var liveEnrichmentPayload struct {
		Items []models.RuntimeFindingEnrichment `json:"items"`
	}
	decodeJSONResponse(t, liveListBody, &liveEnrichmentPayload)
	if len(liveEnrichmentPayload.Items) != 1 {
		t.Fatalf("expected 1 live enrichment, got %d", len(liveEnrichmentPayload.Items))
	}
	if liveEnrichmentPayload.Items[0].ConfidenceAfter != "high" {
		t.Fatalf("expected live enrichment confidence_after high, got %s", liveEnrichmentPayload.Items[0].ConfidenceAfter)
	}

	findingsResponse, findingsBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/findings",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer findingsResponse.Body.Close()

	var findingsPayload struct {
		Items []models.CanonicalFinding `json:"items"`
	}
	decodeJSONResponse(t, findingsBody, &findingsPayload)

	liveFinding, found := findFindingByID(findingsPayload.Items, liveFindingID)
	if !found {
		t.Fatalf("expected finding %s", liveFindingID)
	}
	if !canonicalFindingHasTag(liveFinding, "runtime_confirmed") {
		t.Fatalf("expected finding %s to include runtime_confirmed tag", liveFindingID)
	}
	if !canonicalFindingHasTag(liveFinding, "runtime_event:waf_blocked_request") {
		t.Fatalf("expected finding %s to include runtime event tag", liveFindingID)
	}
	if !canonicalFindingHasEvidence(liveFinding, "runtime_telemetry", "local://evidence/runtime/live-waf-block.json") {
		t.Fatalf("expected finding %s to include runtime evidence ref", liveFindingID)
	}
	if liveFinding.Confidence != "high" {
		t.Fatalf("expected live finding confidence high after enrichment, got %s", liveFinding.Confidence)
	}

	backfillFindingID := fmt.Sprintf("finding-runtime-backfill-%d", time.Now().UTC().UnixNano())
	_, _ = mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/runtime/telemetry/events",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"source_kind":   "edr",
			"source_ref":    "endpoint-agent:alerts",
			"asset_id":      "asset-backfill-runtime",
			"finding_id":    backfillFindingID,
			"event_type":    "edr.alert",
			"severity":      "critical",
			"evidence_refs": []string{"local://evidence/runtime/backfill-edr-alert.json"},
		},
		http.StatusCreated,
	)

	preBackfillResponse, preBackfillBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/runtime/telemetry/enrichments?finding_id="+backfillFindingID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer preBackfillResponse.Body.Close()
	var preBackfillPayload struct {
		Items []models.RuntimeFindingEnrichment `json:"items"`
	}
	decodeJSONResponse(t, preBackfillBody, &preBackfillPayload)
	if len(preBackfillPayload.Items) != 0 {
		t.Fatalf("expected no enrichments before backfill, got %d", len(preBackfillPayload.Items))
	}

	backfillTaskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "repository",
		Target:     "C:/repo/backfill-runtime-enrichment",
		Profile:    "default",
		Tools:      []string{"semgrep"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase10-worker-backfill",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "windows",
		Hostname:        "phase10-backfill-host",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "semgrep",
				SupportedTargetKinds: []string{"repository"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModePassive},
				Labels:               []string{"phase10"},
			},
		},
	})
	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:     backfillTaskID,
		WorkerID:   "phase10-worker-backfill",
		FinalState: "completed",
		ReportedFindings: []models.CanonicalFinding{
			{
				FindingID:     backfillFindingID,
				Category:      "sast_rule_match",
				Title:         "Potential unsafe sink requiring runtime validation",
				Severity:      "medium",
				Confidence:    "medium",
				Status:        "open",
				FirstSeenAt:   now,
				LastSeenAt:    now,
				SchemaVersion: "1.0.0",
			},
		},
	}); err != nil {
		t.Fatalf("finalize backfill finding: %v", err)
	}

	backfillResponse, backfillBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/runtime/telemetry/enrichments?limit=50",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer backfillResponse.Body.Close()
	var backfillResult models.RuntimeEnrichmentBackfillResult
	decodeJSONResponse(t, backfillBody, &backfillResult)
	if backfillResult.ProcessedEvents < 1 {
		t.Fatalf("expected backfill to process at least one event, got %d", backfillResult.ProcessedEvents)
	}
	if backfillResult.EnrichedFindings < 1 {
		t.Fatalf("expected backfill to enrich at least one finding, got %d", backfillResult.EnrichedFindings)
	}

	postBackfillResponse, postBackfillBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/runtime/telemetry/enrichments?finding_id="+backfillFindingID,
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer postBackfillResponse.Body.Close()

	var postBackfillPayload struct {
		Items []models.RuntimeFindingEnrichment `json:"items"`
	}
	decodeJSONResponse(t, postBackfillBody, &postBackfillPayload)
	if len(postBackfillPayload.Items) != 1 {
		t.Fatalf("expected 1 enrichment after backfill, got %d", len(postBackfillPayload.Items))
	}
	if postBackfillPayload.Items[0].ConfidenceAfter != "high" {
		t.Fatalf("expected backfill confidence_after high, got %s", postBackfillPayload.Items[0].ConfidenceAfter)
	}

	findingsAfterBackfillResponse, findingsAfterBackfillBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/findings",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer findingsAfterBackfillResponse.Body.Close()

	var findingsAfterBackfillPayload struct {
		Items []models.CanonicalFinding `json:"items"`
	}
	decodeJSONResponse(t, findingsAfterBackfillBody, &findingsAfterBackfillPayload)

	backfilledFinding, found := findFindingByID(findingsAfterBackfillPayload.Items, backfillFindingID)
	if !found {
		t.Fatalf("expected finding %s after backfill", backfillFindingID)
	}
	if !canonicalFindingHasTag(backfilledFinding, "runtime_confirmed") {
		t.Fatalf("expected backfilled finding %s to include runtime_confirmed tag", backfillFindingID)
	}
	if !canonicalFindingHasTag(backfilledFinding, "runtime_event:edr_alert") {
		t.Fatalf("expected backfilled finding %s to include runtime event tag", backfillFindingID)
	}
	if !canonicalFindingHasEvidence(backfilledFinding, "runtime_telemetry", "local://evidence/runtime/backfill-edr-alert.json") {
		t.Fatalf("expected backfilled finding %s to include runtime evidence ref", backfillFindingID)
	}
	if backfilledFinding.Confidence != "high" {
		t.Fatalf("expected backfilled finding confidence high after enrichment, got %s", backfilledFinding.Confidence)
	}
}

func findFindingByID(items []models.CanonicalFinding, findingID string) (models.CanonicalFinding, bool) {
	targetID := strings.TrimSpace(findingID)
	for _, item := range items {
		if strings.TrimSpace(item.FindingID) == targetID {
			return item, true
		}
	}
	return models.CanonicalFinding{}, false
}

func canonicalFindingHasTag(finding models.CanonicalFinding, tag string) bool {
	needle := strings.ToLower(strings.TrimSpace(tag))
	for _, item := range finding.Tags {
		if strings.ToLower(strings.TrimSpace(item)) == needle {
			return true
		}
	}
	return false
}

func canonicalFindingHasEvidence(finding models.CanonicalFinding, kind string, reference string) bool {
	normalizedKind := strings.ToLower(strings.TrimSpace(kind))
	normalizedRef := strings.TrimSpace(reference)
	for _, item := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(item.Kind)) == normalizedKind &&
			strings.TrimSpace(item.Ref) == normalizedRef {
			return true
		}
	}
	return false
}
