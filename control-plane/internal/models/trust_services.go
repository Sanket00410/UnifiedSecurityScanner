package models

import "time"

type KMSKey struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id,omitempty"`
	KeyRef    string    `json:"key_ref"`
	Provider  string    `json:"provider"`
	Algorithm string    `json:"algorithm"`
	Purpose   string    `json:"purpose"`
	Status    string    `json:"status"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CreateKMSKeyRequest struct {
	KeyRef    string `json:"key_ref"`
	Provider  string `json:"provider,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
}

type KMSEncryptRequest struct {
	KeyRef       string `json:"key_ref"`
	PlaintextB64 string `json:"plaintext_b64"`
	AADB64       string `json:"aad_b64,omitempty"`
}

type KMSEncryptResponse struct {
	KeyRef        string `json:"key_ref"`
	Algorithm     string `json:"algorithm"`
	NonceB64      string `json:"nonce_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

type KMSDecryptRequest struct {
	KeyRef        string `json:"key_ref"`
	NonceB64      string `json:"nonce_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
	AADB64        string `json:"aad_b64,omitempty"`
}

type KMSDecryptResponse struct {
	KeyRef       string `json:"key_ref"`
	PlaintextB64 string `json:"plaintext_b64"`
}

type KMSSignRequest struct {
	KeyRef     string `json:"key_ref"`
	MessageB64 string `json:"message_b64"`
}

type KMSSignResponse struct {
	KeyRef       string `json:"key_ref"`
	Algorithm    string `json:"algorithm"`
	SignatureB64 string `json:"signature_b64"`
}

type KMSVerifyRequest struct {
	KeyRef       string `json:"key_ref"`
	MessageB64   string `json:"message_b64"`
	SignatureB64 string `json:"signature_b64"`
}

type KMSVerifyResponse struct {
	KeyRef string `json:"key_ref"`
	Valid  bool   `json:"valid"`
}

type SecretReference struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id,omitempty"`
	Name          string         `json:"name"`
	Provider      string         `json:"provider"`
	SecretPath    string         `json:"secret_path"`
	SecretVersion string         `json:"secret_version,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	CreatedBy     string         `json:"created_by,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type CreateSecretReferenceRequest struct {
	Name          string         `json:"name"`
	Provider      string         `json:"provider"`
	SecretPath    string         `json:"secret_path"`
	SecretVersion string         `json:"secret_version,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type UpdateSecretReferenceRequest struct {
	Name          string         `json:"name,omitempty"`
	Provider      string         `json:"provider,omitempty"`
	SecretPath    string         `json:"secret_path,omitempty"`
	SecretVersion string         `json:"secret_version,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type SecretLease struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id,omitempty"`
	SecretReferenceID string     `json:"secret_reference_id"`
	WorkerID          string     `json:"worker_id"`
	Status            string     `json:"status"`
	ExpiresAt         time.Time  `json:"expires_at"`
	CreatedBy         string     `json:"created_by,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

type IssueSecretLeaseRequest struct {
	SecretReferenceID string `json:"secret_reference_id"`
	WorkerID          string `json:"worker_id"`
	TTLSeconds        int64  `json:"ttl_seconds,omitempty"`
}

type IssuedSecretLease struct {
	Lease      SecretLease `json:"lease"`
	LeaseToken string      `json:"lease_token"`
}
