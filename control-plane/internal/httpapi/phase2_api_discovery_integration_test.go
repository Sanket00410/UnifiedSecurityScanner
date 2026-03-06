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

func TestPhase2OpenAPIImportAndEndpointInventoryFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase2_api_discovery_it_%d", time.Now().UTC().UnixNano())
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

	importResponse, importBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/assets/apis", cfg.BootstrapAdminToken, "", "", map[string]any{
		"name":     "Checkout API",
		"base_url": "https://api.example.com",
		"source":   "git-webhook",
		"spec": map[string]any{
			"openapi": "3.0.3",
			"security": []map[string]any{
				{"oauth2": []string{}},
			},
			"paths": map[string]any{
				"/v1/checkout/sessions": map[string]any{
					"get": map[string]any{
						"operationId": "listCheckoutSessions",
						"tags":        []string{"checkout"},
					},
					"post": map[string]any{
						"operationId": "createCheckoutSession",
						"tags":        []string{"checkout"},
					},
				},
				"/v1/health": map[string]any{
					"get": map[string]any{
						"operationId": "healthCheck",
						"security":    []any{},
					},
				},
			},
		},
	}, http.StatusCreated)
	defer importResponse.Body.Close()

	var imported models.ImportedAPIAsset
	decodeJSONResponse(t, importBody, &imported)
	if imported.Asset.ID == "" {
		t.Fatal("expected imported api asset id")
	}
	if imported.EndpointCount != 3 {
		t.Fatalf("expected 3 imported endpoints, got %d", imported.EndpointCount)
	}

	listResponse, listBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/assets/apis?limit=20", cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer listResponse.Body.Close()

	var listPayload struct {
		Items []models.APIAsset `json:"items"`
	}
	decodeJSONResponse(t, listBody, &listPayload)
	if len(listPayload.Items) != 1 {
		t.Fatalf("expected 1 api asset, got %d", len(listPayload.Items))
	}
	if listPayload.Items[0].EndpointCount != 3 {
		t.Fatalf("expected endpoint count to be 3, got %d", listPayload.Items[0].EndpointCount)
	}

	endpointsResponse, endpointsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/assets/apis/"+imported.Asset.ID+"/endpoints?limit=100", cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer endpointsResponse.Body.Close()

	var endpointsPayload struct {
		Items []models.APIEndpoint `json:"items"`
	}
	decodeJSONResponse(t, endpointsBody, &endpointsPayload)
	if len(endpointsPayload.Items) != 3 {
		t.Fatalf("expected 3 api endpoints, got %d", len(endpointsPayload.Items))
	}

	unauthenticatedCount := 0
	for _, endpoint := range endpointsPayload.Items {
		if endpoint.Path == "/v1/health" && endpoint.Method == "GET" {
			if endpoint.AuthRequired {
				t.Fatal("expected /v1/health GET to override global security and be unauthenticated")
			}
			unauthenticatedCount++
		}
	}
	if unauthenticatedCount != 1 {
		t.Fatalf("expected 1 unauthenticated endpoint, got %d", unauthenticatedCount)
	}
}

func TestPhase2GraphQLImportAndEndpointInventoryFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase2_graphql_discovery_it_%d", time.Now().UTC().UnixNano())
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

	importResponse, importBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/assets/graphql", cfg.BootstrapAdminToken, "", "", map[string]any{
		"name":          "Graph Payments API",
		"base_url":      "https://graph.example.com",
		"source":        "repo-webhook",
		"endpoint_path": "/graphql",
		"auth_required": true,
		"schema": `
			type Query {
				health: String!
				payment(id: ID!): String
			}
			type Mutation {
				createPayment(amount: Int!): String
			}
		`,
	}, http.StatusCreated)
	defer importResponse.Body.Close()

	var imported models.ImportedAPIAsset
	decodeJSONResponse(t, importBody, &imported)
	if imported.Asset.ID == "" {
		t.Fatal("expected imported graphql api asset id")
	}
	if imported.Asset.SpecVersion != "graphql-sdl" {
		t.Fatalf("expected graphql-sdl spec version, got %s", imported.Asset.SpecVersion)
	}
	if imported.EndpointCount != 3 {
		t.Fatalf("expected 3 imported graphql operations, got %d", imported.EndpointCount)
	}

	endpointsResponse, endpointsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/assets/apis/"+imported.Asset.ID+"/endpoints?limit=100", cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer endpointsResponse.Body.Close()

	var endpointsPayload struct {
		Items []models.APIEndpoint `json:"items"`
	}
	decodeJSONResponse(t, endpointsBody, &endpointsPayload)
	if len(endpointsPayload.Items) != 3 {
		t.Fatalf("expected 3 graphql endpoints, got %d", len(endpointsPayload.Items))
	}

	seenQueryHealth := false
	seenMutationCreate := false
	for _, endpoint := range endpointsPayload.Items {
		if endpoint.Path != "/graphql" || endpoint.Method != "POST" {
			t.Fatalf("expected graphql endpoint POST /graphql, got %s %s", endpoint.Method, endpoint.Path)
		}
		if !endpoint.AuthRequired {
			t.Fatalf("expected graphql endpoint auth_required=true, got false for %s", endpoint.OperationID)
		}
		if endpoint.OperationID == "query.health" {
			seenQueryHealth = true
		}
		if endpoint.OperationID == "mutation.createPayment" {
			seenMutationCreate = true
		}
	}
	if !seenQueryHealth || !seenMutationCreate {
		t.Fatalf("missing expected graphql operations health=%v createPayment=%v", seenQueryHealth, seenMutationCreate)
	}
}
