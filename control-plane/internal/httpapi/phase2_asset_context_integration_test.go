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

	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestPhase2AssetContextMetadataIngestionFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase2_asset_context_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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

	createBuildResponse, createBuildBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/assets/context-events", cfg.BootstrapAdminToken, "", "", map[string]any{
		"asset_id":   "api.internal.service",
		"asset_type": "api",
		"event_kind": "build",
		"source":     "github-actions",
		"metadata": map[string]any{
			"build_id": "build-1001",
			"commit":   "abc123",
		},
	}, http.StatusCreated)
	defer createBuildResponse.Body.Close()

	var createdBuild models.AssetContextEvent
	decodeJSONResponse(t, createBuildBody, &createdBuild)
	if createdBuild.ID == "" {
		t.Fatal("expected created asset context event id")
	}
	if createdBuild.EventKind != "build" {
		t.Fatalf("expected build event kind, got %s", createdBuild.EventKind)
	}

	createDeployResponse, _ := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/assets/context-events", cfg.BootstrapAdminToken, "", "", map[string]any{
		"asset_id":   "api.internal.service",
		"asset_type": "api",
		"event_kind": "deploy",
		"source":     "argo-cd",
		"metadata": map[string]any{
			"release":     "payments-v2.3.1",
			"environment": "production",
		},
	}, http.StatusCreated)
	defer createDeployResponse.Body.Close()

	filteredResponse, filteredBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/assets/context-events?asset_id=api.internal.service&event_kind=build&limit=10", cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer filteredResponse.Body.Close()

	var filteredPayload struct {
		Items []models.AssetContextEvent `json:"items"`
	}
	decodeJSONResponse(t, filteredBody, &filteredPayload)
	if len(filteredPayload.Items) != 1 {
		t.Fatalf("expected 1 build context event, got %d", len(filteredPayload.Items))
	}
	if filteredPayload.Items[0].Metadata["build_id"] != "build-1001" {
		t.Fatalf("expected build metadata build_id, got %#v", filteredPayload.Items[0].Metadata["build_id"])
	}

	listResponse, listBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/assets/context-events?asset_id=api.internal.service&limit=10", cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer listResponse.Body.Close()

	var listPayload struct {
		Items []models.AssetContextEvent `json:"items"`
	}
	decodeJSONResponse(t, listBody, &listPayload)
	if len(listPayload.Items) != 2 {
		t.Fatalf("expected 2 total context events, got %d", len(listPayload.Items))
	}
}
