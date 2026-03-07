package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestPhase5WebhookIntegrationsDispatchFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase5_webhook_integrations_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase5-webhook-secret"
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

	type callbackRequest struct {
		Signature   string
		Custom      string
		EventType   string
		DeliveryID  string
		PayloadBody map[string]any
		Err         string
	}

	callbackCh := make(chan callbackRequest, 10)
	var callbackMu sync.Mutex
	callbackCount := 0
	callbackReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			callbackCh <- callbackRequest{Err: fmt.Sprintf("read webhook callback body: %v", readErr)}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		payload := map[string]any{}
		if unmarshalErr := json.Unmarshal(body, &payload); unmarshalErr != nil {
			callbackCh <- callbackRequest{Err: fmt.Sprintf("decode webhook callback body: %v", unmarshalErr)}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		callbackMu.Lock()
		callbackCount++
		callbackMu.Unlock()

		callbackCh <- callbackRequest{
			Signature:   strings.TrimSpace(r.Header.Get("X-USS-Signature")),
			Custom:      strings.TrimSpace(r.Header.Get("X-Custom-Header")),
			EventType:   strings.TrimSpace(r.Header.Get("X-USS-Event-Type")),
			DeliveryID:  strings.TrimSpace(r.Header.Get("X-USS-Delivery-ID")),
			PayloadBody: payload,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer callbackReceiver.Close()

	client := testServer.Client()

	createWebhookResponse, createWebhookBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/integrations/webhooks",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"name":         "phase5-webhook-primary",
			"endpoint_url": callbackReceiver.URL,
			"event_types":  []string{"scan_job.created"},
			"status":       "active",
			"headers": map[string]any{
				"X-Custom-Header": "phase5",
			},
			"secret": "phase5-signing-secret",
		},
		http.StatusCreated,
	)
	defer createWebhookResponse.Body.Close()

	var webhook models.WebhookIntegration
	decodeJSONResponse(t, createWebhookBody, &webhook)
	if strings.TrimSpace(webhook.ID) == "" {
		t.Fatal("expected webhook integration id")
	}

	createJobResponse, createJobBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/scan-jobs",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"target_kind":  "repo",
			"target":       "https://example.com/org/repo.git",
			"profile":      "quick",
			"requested_by": "phase5-webhook-it",
			"tools":        []string{"semgrep"},
		},
		http.StatusAccepted,
	)
	defer createJobResponse.Body.Close()

	var createdJob models.ScanJob
	decodeJSONResponse(t, createJobBody, &createdJob)
	if strings.TrimSpace(createdJob.ID) == "" {
		t.Fatal("expected created scan job id")
	}

	dispatchResponse, dispatchBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/integrations/webhooks/dispatch",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"event_type": "scan_job.created",
			"limit":      100,
		},
		http.StatusOK,
	)
	defer dispatchResponse.Body.Close()

	var dispatchResult models.DispatchWebhookDeliveriesResult
	decodeJSONResponse(t, dispatchBody, &dispatchResult)
	if dispatchResult.Attempted < 1 {
		t.Fatalf("expected at least one webhook delivery attempt, got %d", dispatchResult.Attempted)
	}
	if dispatchResult.Delivered < 1 {
		t.Fatalf("expected at least one delivered webhook callback, got %d", dispatchResult.Delivered)
	}
	if dispatchResult.ByWebhook[webhook.ID] < 1 {
		t.Fatalf("expected dispatch to include webhook %s, got map=%#v", webhook.ID, dispatchResult.ByWebhook)
	}

	var callback callbackRequest
	select {
	case callback = <-callbackCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for webhook callback")
	}

	if callback.Err != "" {
		t.Fatalf("unexpected webhook callback error: %s", callback.Err)
	}
	if callback.EventType != "scan_job.created" {
		t.Fatalf("expected callback event type scan_job.created, got %s", callback.EventType)
	}
	if callback.Custom != "phase5" {
		t.Fatalf("expected custom header phase5, got %s", callback.Custom)
	}
	if !strings.HasPrefix(callback.Signature, "sha256=") {
		t.Fatalf("expected sha256 signature header, got %s", callback.Signature)
	}
	if strings.TrimSpace(callback.DeliveryID) == "" {
		t.Fatal("expected callback delivery id header")
	}
	if _, ok := callback.PayloadBody["event"]; !ok {
		t.Fatalf("expected callback payload to contain event, got %#v", callback.PayloadBody)
	}

	listWebhookResponse, listWebhookBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/integrations/webhooks?status=active&event_type=scan_job.created",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listWebhookResponse.Body.Close()
	var listWebhookPayload struct {
		Items []models.WebhookIntegration `json:"items"`
	}
	decodeJSONResponse(t, listWebhookBody, &listWebhookPayload)
	if len(listWebhookPayload.Items) != 1 {
		t.Fatalf("expected 1 active webhook integration, got %d", len(listWebhookPayload.Items))
	}

	listDeliveriesResponse, listDeliveriesBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/integrations/webhooks/"+webhook.ID+"/deliveries?status=delivered",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listDeliveriesResponse.Body.Close()
	var listDeliveriesPayload struct {
		Items []models.WebhookDelivery `json:"items"`
	}
	decodeJSONResponse(t, listDeliveriesBody, &listDeliveriesPayload)
	if len(listDeliveriesPayload.Items) < 1 {
		t.Fatal("expected at least one webhook delivery record")
	}
	if listDeliveriesPayload.Items[0].WebhookID != webhook.ID {
		t.Fatalf("expected delivery webhook id %s, got %s", webhook.ID, listDeliveriesPayload.Items[0].WebhookID)
	}
	if listDeliveriesPayload.Items[0].Status != "delivered" {
		t.Fatalf("expected delivered status, got %s", listDeliveriesPayload.Items[0].Status)
	}
}

func TestPhase5WebhookIntegrationsRetryAndDeadLetterFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase5_webhook_retry_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.WorkerSharedSecret = "phase5-webhook-retry-secret"
	cfg.KMSMasterKey = cfg.WorkerSharedSecret

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
	failedCallbacks := int64(0)
	callbackReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.Body.Close()
		failedCallbacks++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"downstream_unavailable"}`))
	}))
	defer callbackReceiver.Close()

	createWebhookResponse, createWebhookBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/integrations/webhooks",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"name":         "phase5-webhook-dead-letter",
			"endpoint_url": callbackReceiver.URL,
			"event_types":  []string{"scan_job.created"},
			"status":       "active",
			"secret":       "phase5-dead-letter-secret",
		},
		http.StatusCreated,
	)
	defer createWebhookResponse.Body.Close()

	var webhook models.WebhookIntegration
	decodeJSONResponse(t, createWebhookBody, &webhook)
	if strings.TrimSpace(webhook.ID) == "" {
		t.Fatal("expected webhook integration id")
	}

	createJobResponse, createJobBody := mustJSONRequest(
		t,
		client,
		http.MethodPost,
		testServer.URL+"/v1/scan-jobs",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		map[string]any{
			"target_kind":  "repo",
			"target":       "https://example.com/org/retry-repo.git",
			"profile":      "quick",
			"requested_by": "phase5-webhook-retry-it",
			"tools":        []string{"semgrep"},
		},
		http.StatusAccepted,
	)
	defer createJobResponse.Body.Close()

	var createdJob models.ScanJob
	decodeJSONResponse(t, createJobBody, &createdJob)
	if strings.TrimSpace(createdJob.ID) == "" {
		t.Fatal("expected created scan job id")
	}

	for attempt := 1; attempt <= 3; attempt++ {
		dispatchResponse, dispatchBody := mustJSONRequest(
			t,
			client,
			http.MethodPost,
			testServer.URL+"/v1/integrations/webhooks/dispatch",
			cfg.BootstrapAdminToken,
			auth.WorkerSecretHeader,
			"",
			map[string]any{
				"event_type": "scan_job.created",
				"limit":      100,
			},
			http.StatusOK,
		)
		defer dispatchResponse.Body.Close()

		var dispatchResult models.DispatchWebhookDeliveriesResult
		decodeJSONResponse(t, dispatchBody, &dispatchResult)
		if dispatchResult.Attempted < 1 {
			t.Fatalf("attempt %d: expected dispatch attempt > 0, got %d", attempt, dispatchResult.Attempted)
		}
		if attempt < 3 {
			time.Sleep((1 << attempt) * time.Second)
		}
	}

	listDeliveriesResponse, listDeliveriesBody := mustJSONRequest(
		t,
		client,
		http.MethodGet,
		testServer.URL+"/v1/integrations/webhooks/"+webhook.ID+"/deliveries?limit=20",
		cfg.BootstrapAdminToken,
		auth.WorkerSecretHeader,
		"",
		nil,
		http.StatusOK,
	)
	defer listDeliveriesResponse.Body.Close()

	var listDeliveriesPayload struct {
		Items []models.WebhookDelivery `json:"items"`
	}
	decodeJSONResponse(t, listDeliveriesBody, &listDeliveriesPayload)
	if len(listDeliveriesPayload.Items) < 3 {
		t.Fatalf("expected at least 3 delivery attempts, got %d", len(listDeliveriesPayload.Items))
	}

	latest := listDeliveriesPayload.Items[0]
	if latest.Status != "dead_letter" {
		t.Fatalf("expected latest delivery status dead_letter, got %s", latest.Status)
	}
	if latest.AttemptCount != 3 {
		t.Fatalf("expected dead-letter attempt_count 3, got %d", latest.AttemptCount)
	}
	if latest.DeadLetteredAt == nil {
		t.Fatal("expected dead_lettered_at to be set on dead_letter delivery")
	}
}
