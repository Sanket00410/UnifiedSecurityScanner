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

func TestPhase2ExternalAssetInventoryFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase2_external_assets_it_%d", time.Now().UTC().UnixNano())
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

	createResponse, createBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/assets/external", cfg.BootstrapAdminToken, "", "", map[string]any{
		"asset_type": "domain",
		"value":      "example.com",
		"source":     "manual",
		"metadata": map[string]any{
			"environment": "production",
		},
	}, http.StatusCreated)
	defer createResponse.Body.Close()

	var created models.ExternalAsset
	decodeJSONResponse(t, createBody, &created)
	if created.ID == "" {
		t.Logf("create external asset response body: %s", string(createBody))
		t.Fatal("expected created external asset id")
	}
	if created.AssetType != "domain" {
		t.Fatalf("expected domain asset type, got %s", created.AssetType)
	}

	syncResponse, syncBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/assets/external/sync", cfg.BootstrapAdminToken, "", "", map[string]any{
		"source": "dns-discovery",
		"assets": []map[string]any{
			{"asset_type": "subdomain", "value": "api.example.com"},
			{"asset_type": "ip", "value": "203.0.113.10"},
		},
	}, http.StatusOK)
	defer syncResponse.Body.Close()

	var synced models.SyncExternalAssetsResult
	decodeJSONResponse(t, syncBody, &synced)
	if synced.ImportedCount != 2 {
		t.Fatalf("expected 2 synced external assets, got %d", synced.ImportedCount)
	}

	listResponse, listBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/assets/external?limit=20", cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer listResponse.Body.Close()

	var listPayload struct {
		Items []models.ExternalAsset `json:"items"`
	}
	decodeJSONResponse(t, listBody, &listPayload)
	if len(listPayload.Items) != 3 {
		t.Fatalf("expected 3 total external assets, got %d", len(listPayload.Items))
	}

	filteredResponse, filteredBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/assets/external?asset_type=domain", cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer filteredResponse.Body.Close()

	var filteredPayload struct {
		Items []models.ExternalAsset `json:"items"`
	}
	decodeJSONResponse(t, filteredBody, &filteredPayload)
	if len(filteredPayload.Items) != 1 {
		t.Fatalf("expected 1 domain external asset, got %d", len(filteredPayload.Items))
	}
}
