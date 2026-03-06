package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func TestPhase7IngestionWebhookFlowCreatesAndReplaysEvents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase7_ingestion_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase7-ingestion-secret"
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

	createSourceResponse, createSourceBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/ingestion/sources", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":        "GitHub Core Repo",
		"provider":    "github",
		"target_kind": "repo",
		"target":      "https://github.com/acme/core",
		"profile":     "balanced",
		"tools":       []string{"semgrep", "trivy", "gitleaks"},
		"labels": map[string]any{
			"repo": "acme/core",
		},
	}, http.StatusCreated)
	defer createSourceResponse.Body.Close()

	var createdSource models.CreatedIngestionSource
	decodeJSONResponse(t, createSourceBody, &createdSource)
	if strings.TrimSpace(createdSource.Source.ID) == "" {
		t.Fatal("expected ingestion source id")
	}
	if strings.TrimSpace(createdSource.IngestToken) == "" {
		t.Fatal("expected ingestion source token")
	}

	webhookResponse, webhookBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, "", ingestionTokenHeader, createdSource.IngestToken, map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-gh-001",
		"requested_by": "github-webhook",
	}, http.StatusAccepted)
	defer webhookResponse.Body.Close()

	var accepted models.IngestionWebhookResponse
	decodeJSONResponse(t, webhookBody, &accepted)
	if accepted.Duplicate {
		t.Fatal("expected first webhook event to be non-duplicate")
	}
	if accepted.Event.Status != "queued" {
		t.Fatalf("expected queued ingestion status, got %s", accepted.Event.Status)
	}
	if accepted.Job == nil || strings.TrimSpace(accepted.Job.ID) == "" {
		t.Fatal("expected webhook to create a scan job")
	}

	scanJobsResponse, scanJobsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/scan-jobs", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer scanJobsResponse.Body.Close()

	var scanJobsPayload struct {
		Items []models.ScanJob `json:"items"`
	}
	decodeJSONResponse(t, scanJobsBody, &scanJobsPayload)
	if len(scanJobsPayload.Items) != 1 {
		t.Fatalf("expected exactly one scan job after first webhook, got %d", len(scanJobsPayload.Items))
	}
	if scanJobsPayload.Items[0].ID != accepted.Job.ID {
		t.Fatalf("expected scan job %s, got %s", accepted.Job.ID, scanJobsPayload.Items[0].ID)
	}

	replayResponse, replayBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, "", ingestionTokenHeader, createdSource.IngestToken, map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-gh-001",
		"requested_by": "github-webhook",
	}, http.StatusOK)
	defer replayResponse.Body.Close()

	var replayed models.IngestionWebhookResponse
	decodeJSONResponse(t, replayBody, &replayed)
	if !replayed.Duplicate {
		t.Fatal("expected replayed webhook to be marked duplicate")
	}
	if replayed.Event.ID != accepted.Event.ID {
		t.Fatalf("expected duplicate event id %s, got %s", accepted.Event.ID, replayed.Event.ID)
	}
	if replayed.Job == nil || replayed.Job.ID != accepted.Job.ID {
		t.Fatalf("expected duplicate replay job id %s, got %#v", accepted.Job.ID, replayed.Job)
	}

	eventsResponse, eventsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/ingestion/events?source_id="+createdSource.Source.ID, cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer eventsResponse.Body.Close()

	var eventsPayload struct {
		Items []models.IngestionEvent `json:"items"`
	}
	decodeJSONResponse(t, eventsBody, &eventsPayload)
	if len(eventsPayload.Items) != 1 {
		t.Fatalf("expected one deduplicated ingestion event, got %d", len(eventsPayload.Items))
	}
	if eventsPayload.Items[0].CreatedScanJobID != accepted.Job.ID {
		t.Fatalf("expected ingestion event to reference job %s, got %s", accepted.Job.ID, eventsPayload.Items[0].CreatedScanJobID)
	}
}

func TestPhase7IngestionWebhookSignatureVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase7_ingestion_signature_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase7-ingestion-secret"
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
	createSourceResponse, createSourceBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/ingestion/sources", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":               "Signed GitHub Ingestion",
		"provider":           "github",
		"signature_required": true,
		"webhook_secret":     "phase7-signing-secret",
		"target_kind":        "repo",
		"target":             "https://github.com/acme/secure",
		"profile":            "balanced",
		"tools":              []string{"semgrep"},
	}, http.StatusCreated)
	defer createSourceResponse.Body.Close()

	var createdSource models.CreatedIngestionSource
	decodeJSONResponse(t, createSourceBody, &createdSource)
	if !createdSource.Source.SignatureRequired {
		t.Fatal("expected created ingestion source signature_required=true")
	}

	signedPayload, err := json.Marshal(map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-signature-ok",
		"requested_by": "github-webhook",
		"payload": map[string]any{
			"ref":   "refs/heads/main",
			"after": "f00dbabe",
			"repository": map[string]any{
				"full_name": "acme/secure",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal signed payload: %v", err)
	}

	validSignature := githubWebhookSignature("phase7-signing-secret", signedPayload)
	validRequest, err := http.NewRequest(http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, bytes.NewReader(signedPayload))
	if err != nil {
		t.Fatalf("create signed webhook request: %v", err)
	}
	validRequest.Header.Set("Content-Type", "application/json")
	validRequest.Header.Set("Authorization", "Bearer "+createdSource.IngestToken)
	validRequest.Header.Set("X-GitHub-Event", "push")
	validRequest.Header.Set("X-Hub-Signature-256", validSignature)

	validResponse, err := client.Do(validRequest)
	if err != nil {
		t.Fatalf("execute signed webhook request: %v", err)
	}
	validBody, err := readAllAndClose(validResponse)
	if err != nil {
		t.Fatalf("read signed webhook response: %v", err)
	}
	if validResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("expected accepted response for valid signature, got %d body=%s", validResponse.StatusCode, string(validBody))
	}

	sha1Payload, err := json.Marshal(map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-signature-sha1",
		"requested_by": "github-webhook",
	})
	if err != nil {
		t.Fatalf("marshal sha1 payload: %v", err)
	}
	validSHA1Request, err := http.NewRequest(http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, bytes.NewReader(sha1Payload))
	if err != nil {
		t.Fatalf("create sha1 webhook request: %v", err)
	}
	validSHA1Request.Header.Set("Content-Type", "application/json")
	validSHA1Request.Header.Set("Authorization", "Bearer "+createdSource.IngestToken)
	validSHA1Request.Header.Set("X-GitHub-Event", "push")
	validSHA1Request.Header.Set("X-Hub-Signature", githubWebhookSignatureSHA1("phase7-signing-secret", sha1Payload))

	validSHA1Response, err := client.Do(validSHA1Request)
	if err != nil {
		t.Fatalf("execute sha1 webhook request: %v", err)
	}
	validSHA1Body, err := readAllAndClose(validSHA1Response)
	if err != nil {
		t.Fatalf("read sha1 webhook response: %v", err)
	}
	if validSHA1Response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected accepted response for valid sha1 signature, got %d body=%s", validSHA1Response.StatusCode, string(validSHA1Body))
	}

	invalidPayload, err := json.Marshal(map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-signature-invalid",
		"requested_by": "github-webhook",
	})
	if err != nil {
		t.Fatalf("marshal invalid payload: %v", err)
	}

	invalidRequest, err := http.NewRequest(http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, bytes.NewReader(invalidPayload))
	if err != nil {
		t.Fatalf("create invalid webhook request: %v", err)
	}
	invalidRequest.Header.Set("Content-Type", "application/json")
	invalidRequest.Header.Set("Authorization", "Bearer "+createdSource.IngestToken)
	invalidRequest.Header.Set("X-GitHub-Event", "push")
	invalidRequest.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")

	invalidResponse, err := client.Do(invalidRequest)
	if err != nil {
		t.Fatalf("execute invalid webhook request: %v", err)
	}
	invalidBody, err := readAllAndClose(invalidResponse)
	if err != nil {
		t.Fatalf("read invalid webhook response: %v", err)
	}
	if invalidResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid signature, got %d body=%s", invalidResponse.StatusCode, string(invalidBody))
	}
}

func TestPhase7IngestionWebhookPolicyBlocksEventType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase7_ingestion_policy_event_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase7-ingestion-secret"

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

	createPolicyResponse, createPolicyBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/policies", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":    "Block GitHub Push Events",
		"scope":   "repository",
		"mode":    "enforce",
		"enabled": true,
		"rules": []map[string]any{
			{
				"effect": "block",
				"field":  "event_type",
				"match":  "exact",
				"values": []string{"github.push"},
			},
		},
	}, http.StatusCreated)
	defer createPolicyResponse.Body.Close()

	var createdPolicy models.Policy
	decodeJSONResponse(t, createPolicyBody, &createdPolicy)
	if strings.TrimSpace(createdPolicy.ID) == "" {
		t.Fatal("expected created policy id")
	}

	createSourceResponse, createSourceBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/ingestion/sources", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":        "Policy-Gated GitHub Source",
		"provider":    "github",
		"target_kind": "repo",
		"target":      "https://github.com/acme/policy",
		"profile":     "balanced",
		"tools":       []string{"semgrep"},
	}, http.StatusCreated)
	defer createSourceResponse.Body.Close()

	var createdSource models.CreatedIngestionSource
	decodeJSONResponse(t, createSourceBody, &createdSource)

	webhookResponse, webhookBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, "", ingestionTokenHeader, createdSource.IngestToken, map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-policy-block",
		"requested_by": "github-webhook",
	}, http.StatusAccepted)
	defer webhookResponse.Body.Close()

	var webhookResult models.IngestionWebhookResponse
	decodeJSONResponse(t, webhookBody, &webhookResult)
	if webhookResult.Event.Status != "policy_denied" {
		t.Fatalf("expected policy_denied ingestion status, got %s", webhookResult.Event.Status)
	}
	if webhookResult.Job != nil {
		t.Fatalf("expected no job for blocked ingestion event, got %#v", webhookResult.Job)
	}
	if webhookResult.Event.PolicyID != createdPolicy.ID {
		t.Fatalf("expected policy id %s, got %s", createdPolicy.ID, webhookResult.Event.PolicyID)
	}

	scanJobsResponse, scanJobsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/scan-jobs", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer scanJobsResponse.Body.Close()

	var scanJobsPayload struct {
		Items []models.ScanJob `json:"items"`
	}
	decodeJSONResponse(t, scanJobsBody, &scanJobsPayload)
	if len(scanJobsPayload.Items) != 0 {
		t.Fatalf("expected 0 scan jobs when event is policy blocked, got %d", len(scanJobsPayload.Items))
	}
}

func githubWebhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func githubWebhookSignatureSHA1(secret string, body []byte) string {
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestPhase7IngestionWebhookSecretRotationInvalidatesOldSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase7_ingestion_rotate_secret_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase7-ingestion-secret"
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
	createSourceResponse, createSourceBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/ingestion/sources", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":               "Rotating GitHub Ingestion Secret",
		"provider":           "github",
		"signature_required": true,
		"webhook_secret":     "phase7-original-signing-secret",
		"target_kind":        "repo",
		"target":             "https://github.com/acme/rotate-secret",
		"profile":            "balanced",
		"tools":              []string{"semgrep"},
	}, http.StatusCreated)
	defer createSourceResponse.Body.Close()

	var createdSource models.CreatedIngestionSource
	decodeJSONResponse(t, createSourceBody, &createdSource)

	originalPayload, err := json.Marshal(map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-rotate-before",
		"requested_by": "github-webhook",
	})
	if err != nil {
		t.Fatalf("marshal original payload: %v", err)
	}

	originalRequest, err := http.NewRequest(http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, bytes.NewReader(originalPayload))
	if err != nil {
		t.Fatalf("create original webhook request: %v", err)
	}
	originalRequest.Header.Set("Content-Type", "application/json")
	originalRequest.Header.Set("Authorization", "Bearer "+createdSource.IngestToken)
	originalRequest.Header.Set("X-GitHub-Event", "push")
	originalRequest.Header.Set("X-Hub-Signature-256", githubWebhookSignature("phase7-original-signing-secret", originalPayload))

	originalResponse, err := client.Do(originalRequest)
	if err != nil {
		t.Fatalf("execute original signed webhook request: %v", err)
	}
	originalBody, err := readAllAndClose(originalResponse)
	if err != nil {
		t.Fatalf("read original signed webhook response: %v", err)
	}
	if originalResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("expected accepted response for original signature, got %d body=%s", originalResponse.StatusCode, string(originalBody))
	}

	rotateResponse, rotateBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/ingestion/sources/"+createdSource.Source.ID+"/rotate-webhook-secret", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer rotateResponse.Body.Close()

	var rotated models.RotateIngestionSourceWebhookSecretResponse
	decodeJSONResponse(t, rotateBody, &rotated)
	if strings.TrimSpace(rotated.WebhookSecret) == "" {
		t.Fatal("expected non-empty rotated webhook secret")
	}
	if rotated.WebhookSecret == "phase7-original-signing-secret" {
		t.Fatal("expected rotated webhook secret to differ from original")
	}
	if !rotated.Source.SignatureRequired {
		t.Fatal("expected rotated source to remain signature_required=true")
	}

	stalePayload, err := json.Marshal(map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-rotate-stale",
		"requested_by": "github-webhook",
	})
	if err != nil {
		t.Fatalf("marshal stale payload: %v", err)
	}

	staleRequest, err := http.NewRequest(http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, bytes.NewReader(stalePayload))
	if err != nil {
		t.Fatalf("create stale webhook request: %v", err)
	}
	staleRequest.Header.Set("Content-Type", "application/json")
	staleRequest.Header.Set("Authorization", "Bearer "+createdSource.IngestToken)
	staleRequest.Header.Set("X-GitHub-Event", "push")
	staleRequest.Header.Set("X-Hub-Signature-256", githubWebhookSignature("phase7-original-signing-secret", stalePayload))

	staleResponse, err := client.Do(staleRequest)
	if err != nil {
		t.Fatalf("execute stale signature webhook request: %v", err)
	}
	staleBody, err := readAllAndClose(staleResponse)
	if err != nil {
		t.Fatalf("read stale signature webhook response: %v", err)
	}
	if staleResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized response for stale signature, got %d body=%s", staleResponse.StatusCode, string(staleBody))
	}

	rotatedPayload, err := json.Marshal(map[string]any{
		"event_type":   "github.push",
		"external_id":  "evt-rotate-after",
		"requested_by": "github-webhook",
	})
	if err != nil {
		t.Fatalf("marshal rotated payload: %v", err)
	}

	rotatedRequest, err := http.NewRequest(http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, bytes.NewReader(rotatedPayload))
	if err != nil {
		t.Fatalf("create rotated webhook request: %v", err)
	}
	rotatedRequest.Header.Set("Content-Type", "application/json")
	rotatedRequest.Header.Set("Authorization", "Bearer "+createdSource.IngestToken)
	rotatedRequest.Header.Set("X-GitHub-Event", "push")
	rotatedRequest.Header.Set("X-Hub-Signature-256", githubWebhookSignature(rotated.WebhookSecret, rotatedPayload))

	rotatedResponse, err := client.Do(rotatedRequest)
	if err != nil {
		t.Fatalf("execute rotated signature webhook request: %v", err)
	}
	rotatedBody, err := readAllAndClose(rotatedResponse)
	if err != nil {
		t.Fatalf("read rotated signature webhook response: %v", err)
	}
	if rotatedResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("expected accepted response for rotated signature, got %d body=%s", rotatedResponse.StatusCode, string(rotatedBody))
	}
}

func TestPhase7IngestionWebhookNormalizesProviderHeadersAndPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase7_ingestion_normalization_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase7-ingestion-secret"

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

	createSourceResponse, createSourceBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/ingestion/sources", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"name":        "GitHub Service",
		"provider":    "github",
		"target_kind": "repo",
		"target":      "https://github.com/acme/service",
		"profile":     "balanced",
		"tools":       []string{"semgrep", "trivy"},
		"labels": map[string]any{
			"team": "appsec",
		},
	}, http.StatusCreated)
	defer createSourceResponse.Body.Close()

	var createdSource models.CreatedIngestionSource
	decodeJSONResponse(t, createSourceBody, &createdSource)

	bodyPayload := map[string]any{
		"payload": map[string]any{
			"ref":   "refs/heads/feature/phase7",
			"after": "cafef00d",
			"repository": map[string]any{
				"full_name": "acme/service",
			},
			"sender": map[string]any{
				"login": "phase7-bot",
			},
		},
	}
	encodedBody, err := json.Marshal(bodyPayload)
	if err != nil {
		t.Fatalf("marshal webhook payload: %v", err)
	}

	webhookRequest, err := http.NewRequest(http.MethodPost, testServer.URL+"/ingest/webhooks/"+createdSource.Source.ID, bytes.NewReader(encodedBody))
	if err != nil {
		t.Fatalf("create webhook request: %v", err)
	}
	webhookRequest.Header.Set("Content-Type", "application/json")
	webhookRequest.Header.Set("Authorization", "Bearer "+createdSource.IngestToken)
	webhookRequest.Header.Set("X-GitHub-Event", "push")
	webhookRequest.Header.Set("X-GitHub-Delivery", "gh-provider-evt-009")

	webhookResponse, err := client.Do(webhookRequest)
	if err != nil {
		t.Fatalf("execute webhook request: %v", err)
	}
	webhookBody, err := readAllAndClose(webhookResponse)
	if err != nil {
		t.Fatalf("read webhook response body: %v", err)
	}
	if webhookResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("expected webhook to be accepted, got %d body=%s", webhookResponse.StatusCode, string(webhookBody))
	}

	var accepted models.IngestionWebhookResponse
	decodeJSONResponse(t, webhookBody, &accepted)
	if accepted.Duplicate {
		t.Fatal("expected provider normalization event to be non-duplicate")
	}
	if accepted.Event.EventType != "github.push" {
		t.Fatalf("expected event type github.push, got %s", accepted.Event.EventType)
	}
	if accepted.Event.ExternalID != "gh-provider-evt-009" {
		t.Fatalf("expected external id from header, got %s", accepted.Event.ExternalID)
	}

	eventsResponse, eventsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/ingestion/events?source_id="+createdSource.Source.ID, cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer eventsResponse.Body.Close()

	var eventsPayload struct {
		Items []models.IngestionEvent `json:"items"`
	}
	decodeJSONResponse(t, eventsBody, &eventsPayload)
	if len(eventsPayload.Items) != 1 {
		t.Fatalf("expected one ingestion event, got %d", len(eventsPayload.Items))
	}

	stored := eventsPayload.Items[0]
	if strings.TrimSpace(stored.CreatedScanJobID) == "" {
		t.Fatal("expected created scan job id on normalized ingestion event")
	}

	labels, ok := stored.Payload["labels"].(map[string]any)
	if !ok {
		t.Fatalf("expected labels map in payload, got %#v", stored.Payload["labels"])
	}
	if labels["repo"] != "acme/service" {
		t.Fatalf("expected repo label from provider payload, got %#v", labels["repo"])
	}
	if labels["branch"] != "feature/phase7" {
		t.Fatalf("expected branch label from provider payload, got %#v", labels["branch"])
	}
	if labels["commit"] != "cafef00d" {
		t.Fatalf("expected commit label from provider payload, got %#v", labels["commit"])
	}
	if labels["team"] != "appsec" {
		t.Fatalf("expected source label to be preserved, got %#v", labels["team"])
	}

	metadata, ok := stored.Payload["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map in payload, got %#v", stored.Payload["metadata"])
	}
	if metadata["provider"] != "github" {
		t.Fatalf("expected provider metadata github, got %#v", metadata["provider"])
	}
	if metadata["sender"] != "phase7-bot" {
		t.Fatalf("expected sender metadata phase7-bot, got %#v", metadata["sender"])
	}
	headers, ok := metadata["webhook_headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected webhook headers metadata, got %#v", metadata["webhook_headers"])
	}
	if headers["x-github-event"] != "push" {
		t.Fatalf("expected x-github-event header in metadata, got %#v", headers["x-github-event"])
	}
	if headers["x-github-delivery"] != "gh-provider-evt-009" {
		t.Fatalf("expected x-github-delivery header in metadata, got %#v", headers["x-github-delivery"])
	}
}
