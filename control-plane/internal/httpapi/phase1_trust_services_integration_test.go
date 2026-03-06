package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	cfg.WorkerSharedSecret = "phase1-trust-worker-secret"
	cfg.EvidenceSigningKey = "phase1-evidence-signing-key"
	cfg.EvidenceSigningKeyID = "phase1-evidence-key-id"
	caCertPEM, caKeyPEM := generateTestCertificateAuthority(t)
	cfg.CertificateAuthorityCertPEM = caCertPEM
	cfg.CertificateAuthorityKeyPEM = caKeyPEM

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

	caBundleResponse, caBundleBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/trust/ca-bundle", cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer caBundleResponse.Body.Close()

	var caBundle models.CertificateAuthorityBundle
	decodeJSONResponse(t, caBundleBody, &caBundle)
	if !strings.Contains(caBundle.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatalf("expected ca bundle pem response, got %s", caBundle.CertificatePEM)
	}

	issueWorkerCertResponse, issueWorkerCertBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/workload-identities/workers/certificates", cfg.BootstrapAdminToken, "", "", map[string]any{
		"worker_id":   "phase1-worker-cert",
		"ttl_seconds": 3600,
		"dns_names":   []string{"phase1-worker-cert.local"},
		"uri_sans":    []string{"spiffe://uss/tenant/local/worker/phase1-worker-cert"},
	}, http.StatusCreated)
	defer issueWorkerCertResponse.Body.Close()

	var issuedCertificate models.IssuedWorkerCertificate
	decodeJSONResponse(t, issueWorkerCertBody, &issuedCertificate)
	if issuedCertificate.Certificate.ID == "" || issuedCertificate.PrivateKeyPEM == "" {
		t.Fatalf("expected issued worker certificate payload, got %+v", issuedCertificate)
	}

	revokeCertResponse, revokeCertBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/workload-identities/workers/certificates/"+issuedCertificate.Certificate.ID+"/revoke", cfg.BootstrapAdminToken, "", "", map[string]any{
		"reason": "rotation-test",
	}, http.StatusOK)
	defer revokeCertResponse.Body.Close()

	var revokedCertificate models.WorkloadCertificate
	decodeJSONResponse(t, revokeCertBody, &revokedCertificate)
	if revokedCertificate.Status != "revoked" {
		t.Fatalf("expected revoked certificate status, got %s", revokedCertificate.Status)
	}

	taskID := createAssignedTask(t, client, testServer.URL, cfg.BootstrapAdminToken, cfg.WorkerSharedSecret, models.CreateScanJobRequest{
		TargetKind: "repo",
		Target:     "c:/repos/phase1-trust-service",
		Profile:    "balanced",
		Tools:      []string{"semgrep"},
	}, models.WorkerRegistrationRequest{
		WorkerID:        "phase1-evidence-worker",
		WorkerVersion:   "1.0.0",
		OperatingSystem: "linux",
		Hostname:        "phase1-evidence-host",
		Capabilities: []models.WorkerCapability{
			{
				AdapterID:            "semgrep",
				SupportedTargetKinds: []string{"repo"},
				SupportedModes:       []models.ExecutionMode{models.ExecutionModePassive},
			},
		},
	})

	evidencePath := filepath.Join(t.TempDir(), "phase1-evidence.log")
	if err := os.WriteFile(evidencePath, []byte("phase1 evidence payload"), 0o600); err != nil {
		t.Fatalf("write phase1 evidence fixture: %v", err)
	}

	finalizeNow := time.Now().UTC()
	if err := store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:        taskID,
		WorkerID:      "phase1-evidence-worker",
		FinalState:    "completed",
		EvidencePaths: []string{evidencePath},
		ReportedFindings: []models.CanonicalFinding{
			{
				SchemaVersion: "1.0.0",
				Category:      "sast_rule_match",
				Title:         "Phase1 evidence check",
				Severity:      "low",
				Confidence:    "medium",
				Status:        "open",
				FirstSeenAt:   finalizeNow,
				LastSeenAt:    finalizeNow,
				Source: models.CanonicalSourceInfo{
					Layer: "code",
					Tool:  "semgrep",
				},
			},
		},
	}); err != nil {
		t.Fatalf("finalize task for evidence integrity flow: %v", err)
	}

	evidenceListResponse, evidenceListBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/evidence?task_id="+taskID, cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer evidenceListResponse.Body.Close()

	var evidenceList models.EvidenceListResult
	decodeJSONResponse(t, evidenceListBody, &evidenceList)
	if len(evidenceList.Items) != 1 {
		t.Fatalf("expected one evidence item, got %d", len(evidenceList.Items))
	}
	if evidenceList.Items[0].Metadata["integrity"] == nil {
		t.Fatalf("expected evidence integrity metadata, got %+v", evidenceList.Items[0].Metadata)
	}

	evidenceVerificationResponse, evidenceVerificationBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/evidence/"+evidenceList.Items[0].ID+"/verify-integrity", cfg.BootstrapAdminToken, "", "", nil, http.StatusOK)
	defer evidenceVerificationResponse.Body.Close()

	var verification models.EvidenceIntegrityVerification
	decodeJSONResponse(t, evidenceVerificationBody, &verification)
	if !verification.Verified || !verification.SignatureValid || !verification.HashMatches {
		t.Fatalf("expected verified evidence integrity payload, got %+v", verification)
	}
}

func generateTestCertificateAuthority(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test ca private key: %v", err)
	}

	now := time.Now().UTC()
	serial := big.NewInt(now.UnixNano())
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "uss-test-ca",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create test ca certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if len(certPEM) == 0 {
		t.Fatal("encode test ca certificate")
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal test ca private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	if len(keyPEM) == 0 {
		t.Fatal("encode test ca private key")
	}

	return string(certPEM), string(keyPEM)
}
