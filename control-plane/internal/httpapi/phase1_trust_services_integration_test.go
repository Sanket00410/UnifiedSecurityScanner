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

func TestPhase1KMSEncryptionAndSecretLeaseFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase1_trust_services_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0
	cfg.KMSMasterKey = "phase1-kms-master-key"
	cfg.SecretLeaseMaxTTL = 30 * time.Minute

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

	kmsKeyResponse, kmsKeyBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/kms/keys", cfg.BootstrapAdminToken, "", "", map[string]any{
		"key_ref":   "tenant-master",
		"provider":  "local",
		"algorithm": "aes-256-gcm",
		"purpose":   "all",
	}, http.StatusCreated)
	defer kmsKeyResponse.Body.Close()

	var key models.KMSKey
	decodeJSONResponse(t, kmsKeyBody, &key)
	if key.KeyRef != "tenant-master" {
		t.Fatalf("expected key_ref tenant-master, got %s", key.KeyRef)
	}

	encryptResponse, encryptBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/kms/encrypt", cfg.BootstrapAdminToken, "", "", map[string]any{
		"key_ref":       "tenant-master",
		"plaintext_b64": "c2VjcmV0LXZhbHVl",
		"aad_b64":       "dGVuYW50LWFhZA==",
	}, http.StatusOK)
	defer encryptResponse.Body.Close()

	var encrypted models.KMSEncryptResponse
	decodeJSONResponse(t, encryptBody, &encrypted)
	if encrypted.CiphertextB64 == "" || encrypted.NonceB64 == "" {
		t.Fatalf("expected encrypted payload, got %+v", encrypted)
	}

	decryptResponse, decryptBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/kms/decrypt", cfg.BootstrapAdminToken, "", "", map[string]any{
		"key_ref":        "tenant-master",
		"nonce_b64":      encrypted.NonceB64,
		"ciphertext_b64": encrypted.CiphertextB64,
		"aad_b64":        "dGVuYW50LWFhZA==",
	}, http.StatusOK)
	defer decryptResponse.Body.Close()

	var decrypted models.KMSDecryptResponse
	decodeJSONResponse(t, decryptBody, &decrypted)
	if decrypted.PlaintextB64 != "c2VjcmV0LXZhbHVl" {
		t.Fatalf("expected decrypted base64 plaintext to round-trip, got %s", decrypted.PlaintextB64)
	}

	signResponse, signBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/kms/sign", cfg.BootstrapAdminToken, "", "", map[string]any{
		"key_ref":     "tenant-master",
		"message_b64": "c2VjdXJlLW1lc3NhZ2U=",
	}, http.StatusOK)
	defer signResponse.Body.Close()

	var signature models.KMSSignResponse
	decodeJSONResponse(t, signBody, &signature)
	if signature.SignatureB64 == "" {
		t.Fatalf("expected signature payload, got %+v", signature)
	}

	verifyResponse, verifyBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/kms/verify", cfg.BootstrapAdminToken, "", "", map[string]any{
		"key_ref":       "tenant-master",
		"message_b64":   "c2VjdXJlLW1lc3NhZ2U=",
		"signature_b64": signature.SignatureB64,
	}, http.StatusOK)
	defer verifyResponse.Body.Close()

	var verified models.KMSVerifyResponse
	decodeJSONResponse(t, verifyBody, &verified)
	if !verified.Valid {
		t.Fatal("expected signature verification to succeed")
	}

	createReferenceResponse, createReferenceBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/secrets/references", cfg.BootstrapAdminToken, "", "", map[string]any{
		"name":           "payments-db-password",
		"provider":       "vault",
		"secret_path":    "kv/apps/payments/password",
		"secret_version": "1",
		"metadata": map[string]any{
			"environment": "prod",
		},
	}, http.StatusCreated)
	defer createReferenceResponse.Body.Close()

	var reference models.SecretReference
	decodeJSONResponse(t, createReferenceBody, &reference)
	if reference.ID == "" {
		t.Fatal("expected secret reference id")
	}

	issueLeaseResponse, issueLeaseBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/secrets/leases/issue", cfg.BootstrapAdminToken, "", "", map[string]any{
		"secret_reference_id": reference.ID,
		"worker_id":           "phase1-secret-worker",
		"ttl_seconds":         300,
	}, http.StatusCreated)
	defer issueLeaseResponse.Body.Close()

	var issuedLease models.IssuedSecretLease
	decodeJSONResponse(t, issueLeaseBody, &issuedLease)
	if issuedLease.Lease.ID == "" || issuedLease.LeaseToken == "" {
		t.Fatalf("expected issued lease and token, got %+v", issuedLease)
	}

	leasesResponse, leasesBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/secrets/leases?secret_reference_id="+reference.ID, cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer leasesResponse.Body.Close()

	var leasesPayload struct {
		Items []models.SecretLease `json:"items"`
	}
	decodeJSONResponse(t, leasesBody, &leasesPayload)
	if len(leasesPayload.Items) != 1 {
		t.Fatalf("expected 1 secret lease, got %d", len(leasesPayload.Items))
	}

	revokeResponse, revokeBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/secrets/leases/"+issuedLease.Lease.ID+"/revoke", cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer revokeResponse.Body.Close()

	var revoked models.SecretLease
	decodeJSONResponse(t, revokeBody, &revoked)
	if revoked.Status != "revoked" {
		t.Fatalf("expected revoked lease status, got %s", revoked.Status)
	}
}
