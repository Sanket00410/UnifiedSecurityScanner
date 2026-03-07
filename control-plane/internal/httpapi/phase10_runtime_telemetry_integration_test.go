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
