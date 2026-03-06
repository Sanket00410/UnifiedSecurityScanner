package httpapi

import (
	"context"
	"fmt"
	"io"
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

func TestPhase0TenantConfigCRUDFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase0_config_it_%d", time.Now().UTC().UnixNano())
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
	token := cfg.BootstrapAdminToken

	upsertResponse, upsertBody := mustJSONRequest(t, client, http.MethodPut, testServer.URL+"/v1/config/retention.evidence", token, "", "", map[string]any{
		"value": map[string]any{
			"days": 120,
		},
	}, http.StatusOK)
	defer upsertResponse.Body.Close()

	var upserted models.TenantConfigEntry
	decodeJSONResponse(t, upsertBody, &upserted)
	if upserted.Key != "retention.evidence" {
		t.Fatalf("expected config key retention.evidence, got %s", upserted.Key)
	}

	getResponse, getBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/config/retention.evidence", token, "", "", nil, http.StatusOK)
	defer getResponse.Body.Close()

	var fetched models.TenantConfigEntry
	decodeJSONResponse(t, getBody, &fetched)
	if fetched.Key != "retention.evidence" {
		t.Fatalf("expected fetched key retention.evidence, got %s", fetched.Key)
	}

	listResponse, listBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/config?prefix=retention", token, "", "", nil, http.StatusOK)
	defer listResponse.Body.Close()

	var listPayload struct {
		Items []models.TenantConfigEntry `json:"items"`
	}
	decodeJSONResponse(t, listBody, &listPayload)
	if len(listPayload.Items) != 1 {
		t.Fatalf("expected 1 tenant config entry, got %d", len(listPayload.Items))
	}

	deleteRequest, err := http.NewRequest(http.MethodDelete, testServer.URL+"/v1/config/retention.evidence", nil)
	if err != nil {
		t.Fatalf("build delete request: %v", err)
	}
	deleteRequest.Header.Set("Authorization", "Bearer "+token)

	deleteResponse, err := client.Do(deleteRequest)
	if err != nil {
		t.Fatalf("execute delete request: %v", err)
	}
	defer deleteResponse.Body.Close()
	_, _ = io.Copy(io.Discard, deleteResponse.Body)
	if deleteResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 for config delete, got %d", deleteResponse.StatusCode)
	}

	notFoundResponse, _ := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/config/retention.evidence", token, "", "", nil, http.StatusNotFound)
	defer notFoundResponse.Body.Close()
}
