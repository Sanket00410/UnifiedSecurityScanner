package worker

import (
	"net/http"
	"testing"

	"unifiedsecurityscanner/platform-services/internal/models"
)

func TestConnectorPayloadForJira(t *testing.T) {
	job := models.PlatformJob{
		JobKind: models.JobKindJiraIssueUpsert,
		Connector: &models.Connector{
			ConnectorKind: models.ConnectorKindJira,
			Metadata: map[string]any{
				"project_key": "SEC",
			},
		},
	}

	payload := connectorPayloadForJob(job, map[string]any{
		"title": "SQL Injection",
		"body":  "Potential SQL injection found",
	})

	fields, ok := payload["fields"].(map[string]any)
	if !ok {
		t.Fatalf("expected fields object")
	}
	if fields["summary"] != "SQL Injection" {
		t.Fatalf("unexpected jira summary: %v", fields["summary"])
	}
}

func TestApplyConnectorAuthBearer(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	applyConnectorAuth(req, models.Connector{
		AuthType:      "bearer",
		AuthSecretRef: "token-value",
	})
	if req.Header.Get("Authorization") != "Bearer token-value" {
		t.Fatalf("missing bearer auth header")
	}
}

func TestSanitizePath(t *testing.T) {
	got := sanitizePath("../tenant/local")
	if got == "" || got == "../tenant/local" || got == "../tenant-local" {
		t.Fatalf("unexpected sanitized value: %q", got)
	}
}
