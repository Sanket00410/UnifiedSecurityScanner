package jobs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/models"
)

var (
	kmsKeySequence          uint64
	kmsOperationSequence    uint64
	secretReferenceSequence uint64
	secretLeaseSequence     uint64
)

func (s *Store) ListKMSKeysForTenant(ctx context.Context, tenantID string, limit int) ([]models.KMSKey, error) {
	tenantID = strings.TrimSpace(tenantID)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, key_ref, provider, algorithm, purpose, status, created_by, created_at, updated_at
		FROM kms_keys
		WHERE tenant_id = $1
		ORDER BY updated_at DESC, id DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list kms keys: %w", err)
	}
	defer rows.Close()

	out := make([]models.KMSKey, 0, limit)
	for rows.Next() {
		item, err := scanKMSKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan kms key row: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate kms key rows: %w", err)
	}

	return out, nil
}

func (s *Store) CreateKMSKeyForTenant(ctx context.Context, tenantID string, actor string, request models.CreateKMSKeyRequest) (models.KMSKey, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	keyRef := strings.TrimSpace(request.KeyRef)
	if keyRef == "" {
		return models.KMSKey{}, fmt.Errorf("key_ref is required")
	}

	now := time.Now().UTC()
	item := models.KMSKey{
		ID:        nextKMSKeyID(),
		TenantID:  tenantID,
		KeyRef:    keyRef,
		Provider:  normalizeKMSProvider(request.Provider),
		Algorithm: normalizeKMSAlgorithm(request.Algorithm),
		Purpose:   normalizeKMSPurpose(request.Purpose),
		Status:    "active",
		CreatedBy: actor,
		CreatedAt: now,
		UpdatedAt: now,
	}

	saltBytes, err := randomBytes(16)
	if err != nil {
		return models.KMSKey{}, fmt.Errorf("generate kms key salt: %w", err)
	}
	keySalt := base64.RawURLEncoding.EncodeToString(saltBytes)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO kms_keys (
			id, tenant_id, key_ref, provider, algorithm, purpose, status, key_salt, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)
	`, item.ID, item.TenantID, item.KeyRef, item.Provider, item.Algorithm, item.Purpose, item.Status, keySalt, item.CreatedBy, item.CreatedAt, item.UpdatedAt)
	if err != nil {
		return models.KMSKey{}, fmt.Errorf("insert kms key: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "kms_key.created",
		SourceService: "control-plane",
		AggregateType: "kms_key",
		AggregateID:   item.ID,
		Payload: map[string]any{
			"key_ref":    item.KeyRef,
			"provider":   item.Provider,
			"algorithm":  item.Algorithm,
			"purpose":    item.Purpose,
			"created_by": actor,
		},
		CreatedAt: now,
	})

	return item, nil
}

func (s *Store) EncryptWithKMSForTenant(ctx context.Context, tenantID string, request models.KMSEncryptRequest) (models.KMSEncryptResponse, error) {
	keyRecord, err := s.loadKMSKeyByReference(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(request.KeyRef))
	if err != nil {
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "encrypt", "failed", err.Error())
		return models.KMSEncryptResponse{}, err
	}
	if !allowsKMSEncrypt(keyRecord.Key.Purpose) {
		err := fmt.Errorf("kms key purpose %s cannot encrypt", keyRecord.Key.Purpose)
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "encrypt", "failed", err.Error())
		return models.KMSEncryptResponse{}, err
	}

	plaintext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.PlaintextB64))
	if err != nil {
		return models.KMSEncryptResponse{}, fmt.Errorf("plaintext_b64 must be valid base64")
	}
	aad, err := decodeOptionalBase64(strings.TrimSpace(request.AADB64))
	if err != nil {
		return models.KMSEncryptResponse{}, fmt.Errorf("aad_b64 must be valid base64")
	}

	keyBytes, err := s.deriveKMSKeyMaterial(keyRecord, "enc")
	if err != nil {
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "encrypt", "failed", err.Error())
		return models.KMSEncryptResponse{}, err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return models.KMSEncryptResponse{}, fmt.Errorf("create cipher for encryption: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return models.KMSEncryptResponse{}, fmt.Errorf("create gcm for encryption: %w", err)
	}

	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return models.KMSEncryptResponse{}, fmt.Errorf("generate nonce for encryption: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	response := models.KMSEncryptResponse{
		KeyRef:        keyRecord.Key.KeyRef,
		Algorithm:     keyRecord.Key.Algorithm,
		NonceB64:      base64.StdEncoding.EncodeToString(nonce),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}

	_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "encrypt", "success", "")
	return response, nil
}

func (s *Store) DecryptWithKMSForTenant(ctx context.Context, tenantID string, request models.KMSDecryptRequest) (models.KMSDecryptResponse, error) {
	keyRecord, err := s.loadKMSKeyByReference(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(request.KeyRef))
	if err != nil {
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "decrypt", "failed", err.Error())
		return models.KMSDecryptResponse{}, err
	}
	if !allowsKMSEncrypt(keyRecord.Key.Purpose) {
		err := fmt.Errorf("kms key purpose %s cannot decrypt", keyRecord.Key.Purpose)
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "decrypt", "failed", err.Error())
		return models.KMSDecryptResponse{}, err
	}

	nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.NonceB64))
	if err != nil {
		return models.KMSDecryptResponse{}, fmt.Errorf("nonce_b64 must be valid base64")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.CiphertextB64))
	if err != nil {
		return models.KMSDecryptResponse{}, fmt.Errorf("ciphertext_b64 must be valid base64")
	}
	aad, err := decodeOptionalBase64(strings.TrimSpace(request.AADB64))
	if err != nil {
		return models.KMSDecryptResponse{}, fmt.Errorf("aad_b64 must be valid base64")
	}

	keyBytes, err := s.deriveKMSKeyMaterial(keyRecord, "enc")
	if err != nil {
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "decrypt", "failed", err.Error())
		return models.KMSDecryptResponse{}, err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return models.KMSDecryptResponse{}, fmt.Errorf("create cipher for decryption: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return models.KMSDecryptResponse{}, fmt.Errorf("create gcm for decryption: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "decrypt", "failed", "decryption failed")
		return models.KMSDecryptResponse{}, fmt.Errorf("decrypt ciphertext: %w", err)
	}

	_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "decrypt", "success", "")
	return models.KMSDecryptResponse{
		KeyRef:       keyRecord.Key.KeyRef,
		PlaintextB64: base64.StdEncoding.EncodeToString(plaintext),
	}, nil
}

func (s *Store) SignWithKMSForTenant(ctx context.Context, tenantID string, request models.KMSSignRequest) (models.KMSSignResponse, error) {
	keyRecord, err := s.loadKMSKeyByReference(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(request.KeyRef))
	if err != nil {
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "sign", "failed", err.Error())
		return models.KMSSignResponse{}, err
	}
	if !allowsKMSSign(keyRecord.Key.Purpose) {
		err := fmt.Errorf("kms key purpose %s cannot sign", keyRecord.Key.Purpose)
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "sign", "failed", err.Error())
		return models.KMSSignResponse{}, err
	}

	message, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.MessageB64))
	if err != nil {
		return models.KMSSignResponse{}, fmt.Errorf("message_b64 must be valid base64")
	}

	signingKey, err := s.deriveKMSKeyMaterial(keyRecord, "sign")
	if err != nil {
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "sign", "failed", err.Error())
		return models.KMSSignResponse{}, err
	}

	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write(message)
	signature := mac.Sum(nil)

	_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "sign", "success", "")
	return models.KMSSignResponse{
		KeyRef:       keyRecord.Key.KeyRef,
		Algorithm:    "hmac-sha256",
		SignatureB64: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (s *Store) VerifyWithKMSForTenant(ctx context.Context, tenantID string, request models.KMSVerifyRequest) (models.KMSVerifyResponse, error) {
	keyRecord, err := s.loadKMSKeyByReference(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(request.KeyRef))
	if err != nil {
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "verify", "failed", err.Error())
		return models.KMSVerifyResponse{}, err
	}
	if !allowsKMSSign(keyRecord.Key.Purpose) {
		err := fmt.Errorf("kms key purpose %s cannot verify", keyRecord.Key.Purpose)
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "verify", "failed", err.Error())
		return models.KMSVerifyResponse{}, err
	}

	message, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.MessageB64))
	if err != nil {
		return models.KMSVerifyResponse{}, fmt.Errorf("message_b64 must be valid base64")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.SignatureB64))
	if err != nil {
		return models.KMSVerifyResponse{}, fmt.Errorf("signature_b64 must be valid base64")
	}

	signingKey, err := s.deriveKMSKeyMaterial(keyRecord, "sign")
	if err != nil {
		_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "verify", "failed", err.Error())
		return models.KMSVerifyResponse{}, err
	}

	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write(message)
	expected := mac.Sum(nil)
	valid := subtle.ConstantTimeCompare(signature, expected) == 1

	_ = s.recordKMSOperation(ctx, tenantID, request.KeyRef, "verify", "success", "")
	return models.KMSVerifyResponse{
		KeyRef: keyRecord.Key.KeyRef,
		Valid:  valid,
	}, nil
}

func (s *Store) ListSecretReferencesForTenant(ctx context.Context, tenantID string, limit int) ([]models.SecretReference, error) {
	tenantID = strings.TrimSpace(tenantID)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, provider, secret_path, secret_version, metadata_json, created_by, created_at, updated_at
		FROM secret_references
		WHERE tenant_id = $1
		ORDER BY updated_at DESC, id DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list secret references: %w", err)
	}
	defer rows.Close()

	out := make([]models.SecretReference, 0, limit)
	for rows.Next() {
		item, err := scanSecretReference(rows)
		if err != nil {
			return nil, fmt.Errorf("scan secret reference row: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secret references: %w", err)
	}

	return out, nil
}

func (s *Store) GetSecretReferenceForTenant(ctx context.Context, tenantID string, referenceID string) (models.SecretReference, bool, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, provider, secret_path, secret_version, metadata_json, created_by, created_at, updated_at
		FROM secret_references
		WHERE tenant_id = $1
		  AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(referenceID))

	item, err := scanSecretReference(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.SecretReference{}, false, nil
		}
		return models.SecretReference{}, false, fmt.Errorf("get secret reference: %w", err)
	}

	return item, true, nil
}

func (s *Store) CreateSecretReferenceForTenant(ctx context.Context, tenantID string, actor string, request models.CreateSecretReferenceRequest) (models.SecretReference, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	now := time.Now().UTC()
	item := models.SecretReference{
		ID:            nextSecretReferenceID(),
		TenantID:      tenantID,
		Name:          strings.TrimSpace(request.Name),
		Provider:      normalizeSecretProvider(request.Provider),
		SecretPath:    strings.TrimSpace(request.SecretPath),
		SecretVersion: strings.TrimSpace(request.SecretVersion),
		Metadata:      request.Metadata,
		CreatedBy:     actor,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	if item.Name == "" || item.SecretPath == "" {
		return models.SecretReference{}, fmt.Errorf("name and secret_path are required")
	}

	metadataJSON, err := json.Marshal(item.Metadata)
	if err != nil {
		return models.SecretReference{}, fmt.Errorf("marshal secret reference metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO secret_references (
			id, tenant_id, name, provider, secret_path, secret_version, metadata_json, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
	`, item.ID, item.TenantID, item.Name, item.Provider, item.SecretPath, item.SecretVersion, metadataJSON, item.CreatedBy, item.CreatedAt, item.UpdatedAt)
	if err != nil {
		return models.SecretReference{}, fmt.Errorf("insert secret reference: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "secret_reference.created",
		SourceService: "control-plane",
		AggregateType: "secret_reference",
		AggregateID:   item.ID,
		Payload: map[string]any{
			"name":       item.Name,
			"provider":   item.Provider,
			"created_by": actor,
		},
		CreatedAt: now,
	})

	return item, nil
}

func (s *Store) UpdateSecretReferenceForTenant(ctx context.Context, tenantID string, referenceID string, actor string, request models.UpdateSecretReferenceRequest) (models.SecretReference, bool, error) {
	current, found, err := s.GetSecretReferenceForTenant(ctx, tenantID, referenceID)
	if err != nil || !found {
		return models.SecretReference{}, found, err
	}

	if value := strings.TrimSpace(request.Name); value != "" {
		current.Name = value
	}
	if value := strings.TrimSpace(request.Provider); value != "" {
		current.Provider = normalizeSecretProvider(value)
	}
	if value := strings.TrimSpace(request.SecretPath); value != "" {
		current.SecretPath = value
	}
	if request.SecretVersion != "" {
		current.SecretVersion = strings.TrimSpace(request.SecretVersion)
	}
	if request.Metadata != nil {
		current.Metadata = request.Metadata
	}
	if current.Metadata == nil {
		current.Metadata = map[string]any{}
	}
	current.UpdatedAt = time.Now().UTC()

	metadataJSON, err := json.Marshal(current.Metadata)
	if err != nil {
		return models.SecretReference{}, false, fmt.Errorf("marshal secret reference metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE secret_references
		SET name = $3,
		    provider = $4,
		    secret_path = $5,
		    secret_version = $6,
		    metadata_json = $7,
		    updated_at = $8
		WHERE tenant_id = $1
		  AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(referenceID), current.Name, current.Provider, current.SecretPath, current.SecretVersion, metadataJSON, current.UpdatedAt)
	if err != nil {
		return models.SecretReference{}, false, fmt.Errorf("update secret reference: %w", err)
	}

	return current, true, nil
}

func (s *Store) DeleteSecretReferenceForTenant(ctx context.Context, tenantID string, referenceID string) (bool, error) {
	result, err := s.pool.Exec(ctx, `
		DELETE FROM secret_references
		WHERE tenant_id = $1
		  AND id = $2
	`, strings.TrimSpace(tenantID), strings.TrimSpace(referenceID))
	if err != nil {
		return false, fmt.Errorf("delete secret reference: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

func (s *Store) ListSecretLeasesForTenant(ctx context.Context, tenantID string, referenceID string, limit int) ([]models.SecretLease, error) {
	tenantID = strings.TrimSpace(tenantID)
	referenceID = strings.TrimSpace(referenceID)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, secret_reference_id, worker_id, status, expires_at, created_by, created_at, updated_at, revoked_at
		FROM secret_leases
		WHERE tenant_id = $1
		  AND ($2 = '' OR secret_reference_id = $2)
		ORDER BY updated_at DESC, id DESC
		LIMIT $3
	`, tenantID, referenceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list secret leases: %w", err)
	}
	defer rows.Close()

	out := make([]models.SecretLease, 0, limit)
	for rows.Next() {
		item, err := scanSecretLease(rows)
		if err != nil {
			return nil, fmt.Errorf("scan secret lease row: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secret leases: %w", err)
	}

	return out, nil
}

func (s *Store) IssueSecretLeaseForTenant(ctx context.Context, tenantID string, actor string, request models.IssueSecretLeaseRequest) (models.IssuedSecretLease, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	referenceID := strings.TrimSpace(request.SecretReferenceID)
	workerID := strings.TrimSpace(request.WorkerID)
	if referenceID == "" || workerID == "" {
		return models.IssuedSecretLease{}, fmt.Errorf("secret_reference_id and worker_id are required")
	}

	_, found, err := s.GetSecretReferenceForTenant(ctx, tenantID, referenceID)
	if err != nil {
		return models.IssuedSecretLease{}, err
	}
	if !found {
		return models.IssuedSecretLease{}, ErrSecretReferenceNotFound
	}

	maxTTL := s.secretLeaseMaxTTL
	if maxTTL <= 0 {
		maxTTL = 30 * time.Minute
	}
	ttl := 10 * time.Minute
	if request.TTLSeconds > 0 {
		ttl = time.Duration(request.TTLSeconds) * time.Second
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}

	now := time.Now().UTC()
	issued, err := issueSecretLeaseTx(ctx, s.pool, tenantID, actor, workerID, referenceID, ttl, now)
	if err != nil {
		return models.IssuedSecretLease{}, err
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "secret_lease.issued",
		SourceService: "control-plane",
		AggregateType: "secret_lease",
		AggregateID:   issued.Lease.ID,
		Payload: map[string]any{
			"secret_reference_id": issued.Lease.SecretReferenceID,
			"worker_id":           issued.Lease.WorkerID,
			"expires_at":          issued.Lease.ExpiresAt,
		},
		CreatedAt: now,
	})

	return issued, nil
}

func issueSecretLeaseTx(
	ctx context.Context,
	exec interface {
		Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	},
	tenantID string,
	actor string,
	workerID string,
	referenceID string,
	ttl time.Duration,
	now time.Time,
) (models.IssuedSecretLease, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	workerID = strings.TrimSpace(workerID)
	referenceID = strings.TrimSpace(referenceID)
	if workerID == "" || referenceID == "" {
		return models.IssuedSecretLease{}, fmt.Errorf("worker_id and secret_reference_id are required")
	}

	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	expiresAt := now.Add(ttl)
	leaseTokenRaw, err := randomBytes(24)
	if err != nil {
		return models.IssuedSecretLease{}, fmt.Errorf("generate secret lease token: %w", err)
	}
	leaseToken := hex.EncodeToString(leaseTokenRaw)

	item := models.SecretLease{
		ID:                nextSecretLeaseID(),
		TenantID:          tenantID,
		SecretReferenceID: referenceID,
		WorkerID:          workerID,
		Status:            "active",
		ExpiresAt:         expiresAt,
		CreatedBy:         actor,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	_, err = exec.Exec(ctx, `
		INSERT INTO secret_leases (
			id, tenant_id, secret_reference_id, worker_id, lease_token_hash, status,
			expires_at, created_by, created_at, updated_at, revoked_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, NULL
		)
	`, item.ID, item.TenantID, item.SecretReferenceID, item.WorkerID, auth.TokenHash(leaseToken), item.Status, item.ExpiresAt, item.CreatedBy, item.CreatedAt, item.UpdatedAt)
	if err != nil {
		return models.IssuedSecretLease{}, fmt.Errorf("insert secret lease: %w", err)
	}

	return models.IssuedSecretLease{
		Lease:      item,
		LeaseToken: leaseToken,
	}, nil
}

func (s *Store) RevokeSecretLeaseForTenant(ctx context.Context, tenantID string, leaseID string, actor string) (models.SecretLease, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	leaseID = strings.TrimSpace(leaseID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	now := time.Now().UTC()
	result, err := s.pool.Exec(ctx, `
		UPDATE secret_leases
		SET status = 'revoked',
		    updated_at = $3,
		    revoked_at = $3
		WHERE tenant_id = $1
		  AND id = $2
		  AND status <> 'revoked'
	`, tenantID, leaseID, now)
	if err != nil {
		return models.SecretLease{}, false, fmt.Errorf("revoke secret lease: %w", err)
	}
	if result.RowsAffected() == 0 {
		return models.SecretLease{}, false, nil
	}

	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, secret_reference_id, worker_id, status, expires_at, created_by, created_at, updated_at, revoked_at
		FROM secret_leases
		WHERE tenant_id = $1
		  AND id = $2
	`, tenantID, leaseID)
	item, err := scanSecretLease(row)
	if err != nil {
		return models.SecretLease{}, false, fmt.Errorf("load revoked secret lease: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "secret_lease.revoked",
		SourceService: "control-plane",
		AggregateType: "secret_lease",
		AggregateID:   item.ID,
		Payload: map[string]any{
			"secret_reference_id": item.SecretReferenceID,
			"worker_id":           item.WorkerID,
			"revoked_by":          actor,
		},
		CreatedAt: now,
	})

	return item, true, nil
}

type kmsKeyRecord struct {
	Key  models.KMSKey
	Salt string
}

func (s *Store) loadKMSKeyByReference(ctx context.Context, tenantID string, keyRef string) (kmsKeyRecord, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, key_ref, provider, algorithm, purpose, status, created_by, created_at, updated_at, key_salt
		FROM kms_keys
		WHERE tenant_id = $1
		  AND key_ref = $2
	`, tenantID, keyRef)

	var record kmsKeyRecord
	err := row.Scan(
		&record.Key.ID,
		&record.Key.TenantID,
		&record.Key.KeyRef,
		&record.Key.Provider,
		&record.Key.Algorithm,
		&record.Key.Purpose,
		&record.Key.Status,
		&record.Key.CreatedBy,
		&record.Key.CreatedAt,
		&record.Key.UpdatedAt,
		&record.Salt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return kmsKeyRecord{}, ErrKMSKeyNotFound
		}
		return kmsKeyRecord{}, fmt.Errorf("load kms key by reference: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(record.Key.Status), "active") {
		return kmsKeyRecord{}, fmt.Errorf("kms key %s is not active", record.Key.KeyRef)
	}

	return record, nil
}

func (s *Store) deriveKMSKeyMaterial(record kmsKeyRecord, usage string) ([]byte, error) {
	masterKey := strings.TrimSpace(s.kmsMasterKey)
	if masterKey == "" {
		return nil, fmt.Errorf("kms master key is not configured")
	}

	mac := hmac.New(sha256.New, []byte(masterKey))
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(record.Key.TenantID))))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(record.Key.KeyRef))))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(strings.TrimSpace(record.Salt)))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(usage))))
	sum := mac.Sum(nil)
	return sum[:32], nil
}

func (s *Store) recordKMSOperation(ctx context.Context, tenantID string, keyRef string, operation string, status string, errorMessage string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO kms_operation_logs (
			id, tenant_id, key_ref, operation, status, error_message, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
	`, nextKMSOperationID(), strings.TrimSpace(tenantID), strings.TrimSpace(keyRef), strings.TrimSpace(operation), strings.TrimSpace(status), strings.TrimSpace(errorMessage), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("record kms operation: %w", err)
	}
	return nil
}

func scanKMSKey(row interface{ Scan(dest ...any) error }) (models.KMSKey, error) {
	var item models.KMSKey
	err := row.Scan(&item.ID, &item.TenantID, &item.KeyRef, &item.Provider, &item.Algorithm, &item.Purpose, &item.Status, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return models.KMSKey{}, err
	}
	return item, nil
}

func scanSecretReference(row interface{ Scan(dest ...any) error }) (models.SecretReference, error) {
	var (
		item         models.SecretReference
		metadataJSON []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.Name,
		&item.Provider,
		&item.SecretPath,
		&item.SecretVersion,
		&metadataJSON,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		return models.SecretReference{}, err
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &item.Metadata); err != nil {
			return models.SecretReference{}, fmt.Errorf("decode secret metadata: %w", err)
		}
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}

	return item, nil
}

func scanSecretLease(row interface{ Scan(dest ...any) error }) (models.SecretLease, error) {
	var item models.SecretLease
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.SecretReferenceID,
		&item.WorkerID,
		&item.Status,
		&item.ExpiresAt,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.RevokedAt,
	)
	if err != nil {
		return models.SecretLease{}, err
	}
	return item, nil
}

func normalizeKMSProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "aws-kms", "gcp-kms", "azure-kv", "vault-transit", "hsm":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "local"
	}
}

func normalizeKMSAlgorithm(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "aes-256-gcm", "hmac-sha256":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "aes-256-gcm"
	}
}

func normalizeKMSPurpose(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "encrypt_decrypt", "sign_verify", "all":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "encrypt_decrypt"
	}
}

func allowsKMSEncrypt(purpose string) bool {
	normalized := strings.ToLower(strings.TrimSpace(purpose))
	return normalized == "encrypt_decrypt" || normalized == "all"
}

func allowsKMSSign(purpose string) bool {
	normalized := strings.ToLower(strings.TrimSpace(purpose))
	return normalized == "sign_verify" || normalized == "all"
}

func normalizeSecretProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "vault", "aws-secrets-manager", "gcp-secret-manager", "azure-key-vault":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "vault"
	}
}

func decodeOptionalBase64(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(trimmed)
}

func randomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, nil
	}
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return nil, err
	}
	return buffer, nil
}

func nextKMSKeyID() string {
	sequence := atomic.AddUint64(&kmsKeySequence, 1)
	return fmt.Sprintf("kms-key-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextKMSOperationID() string {
	sequence := atomic.AddUint64(&kmsOperationSequence, 1)
	return fmt.Sprintf("kms-op-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextSecretReferenceID() string {
	sequence := atomic.AddUint64(&secretReferenceSequence, 1)
	return fmt.Sprintf("secret-ref-%d-%06d", time.Now().UTC().Unix(), sequence)
}

func nextSecretLeaseID() string {
	sequence := atomic.AddUint64(&secretLeaseSequence, 1)
	return fmt.Sprintf("secret-lease-%d-%06d", time.Now().UTC().Unix(), sequence)
}
