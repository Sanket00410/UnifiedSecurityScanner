package jobs

import (
	"encoding/json"
	"testing"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestParseOpenAPIEndpointsHandlesSecurityOverrides(t *testing.T) {
	t.Parallel()

	spec := map[string]any{
		"openapi": "3.0.3",
		"security": []map[string]any{
			{"oauth2": []string{}},
		},
		"paths": map[string]any{
			"/v1/users": map[string]any{
				"get": map[string]any{
					"operationId": "listUsers",
					"tags":        []string{"users"},
				},
			},
			"/v1/health": map[string]any{
				"get": map[string]any{
					"operationId": "health",
					"security":    []any{},
				},
			},
		},
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal openapi spec: %v", err)
	}

	version, endpoints, err := parseOpenAPIEndpoints(encoded)
	if err != nil {
		t.Fatalf("parse openapi endpoints: %v", err)
	}

	if version != "3.0.3" {
		t.Fatalf("expected version 3.0.3, got %s", version)
	}
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}

	foundHealth := false
	foundUsers := false
	for _, endpoint := range endpoints {
		switch endpoint.Path + ":" + endpoint.Method {
		case "/v1/health:GET":
			foundHealth = true
			if endpoint.AuthRequired {
				t.Fatal("expected /v1/health GET to be unauthenticated")
			}
		case "/v1/users:GET":
			foundUsers = true
			if !endpoint.AuthRequired {
				t.Fatal("expected /v1/users GET to inherit global auth requirement")
			}
		}
	}

	if !foundHealth || !foundUsers {
		t.Fatalf("missing expected endpoints: health=%v users=%v", foundHealth, foundUsers)
	}
}

func TestParseOpenAPIEndpointsRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	_, _, err := parseOpenAPIEndpoints(json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected invalid json parse error")
	}
}

func TestParseGraphQLSchemaEndpointsBuildsOperationInventory(t *testing.T) {
	t.Parallel()

	request := models.ImportGraphQLSchemaRequest{
		Name:         "Graph API",
		EndpointPath: "/graphql",
		Schema: `
			type Query {
				health: String!
				payment(id: ID!): String
			}
			type Mutation {
				createPayment(amount: Int!): String
			}
		`,
	}

	version, endpoints, rawSchema, err := parseGraphQLSchemaEndpoints(request)
	if err != nil {
		t.Fatalf("parse graphql schema endpoints: %v", err)
	}
	if version != "graphql-sdl" {
		t.Fatalf("expected graphql-sdl version, got %s", version)
	}
	if rawSchema == "" {
		t.Fatal("expected raw schema in parser response")
	}
	if len(endpoints) != 3 {
		t.Fatalf("expected 3 graphql operations, got %d", len(endpoints))
	}

	hasQueryHealth := false
	hasMutationCreatePayment := false
	for _, endpoint := range endpoints {
		if endpoint.Path != "/graphql" || endpoint.Method != "POST" {
			t.Fatalf("expected POST /graphql endpoint, got %s %s", endpoint.Method, endpoint.Path)
		}
		if endpoint.OperationID == "query.health" {
			hasQueryHealth = true
		}
		if endpoint.OperationID == "mutation.createPayment" {
			hasMutationCreatePayment = true
		}
	}
	if !hasQueryHealth || !hasMutationCreatePayment {
		t.Fatalf("missing graphql operations health=%v createPayment=%v", hasQueryHealth, hasMutationCreatePayment)
	}
}

func TestParseGraphQLSchemaEndpointsRejectsMissingSchema(t *testing.T) {
	t.Parallel()

	_, _, _, err := parseGraphQLSchemaEndpoints(models.ImportGraphQLSchemaRequest{
		Name:   "Graph API",
		Schema: " ",
	})
	if err == nil {
		t.Fatal("expected missing schema error")
	}
}
