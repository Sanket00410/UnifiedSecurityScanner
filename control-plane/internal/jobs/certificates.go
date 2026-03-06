package jobs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

var workloadCertificateSequence uint64

func (s *Store) GetCertificateAuthorityBundle() (models.CertificateAuthorityBundle, error) {
	certificatePEM := strings.TrimSpace(s.certificateAuthorityCertPEM)
	if certificatePEM == "" {
		return models.CertificateAuthorityBundle{}, ErrCertificateAuthorityDisabled
	}

	return models.CertificateAuthorityBundle{
		CertificatePEM: certificatePEM,
	}, nil
}

func (s *Store) ListWorkloadCertificatesForTenant(ctx context.Context, tenantID string, subjectID string, limit int) ([]models.WorkloadCertificate, error) {
	tenantID = strings.TrimSpace(tenantID)
	subjectID = strings.TrimSpace(subjectID)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			id, tenant_id, subject_type, subject_id, serial_number, fingerprint_sha256,
			certificate_pem, issued_by, status, issued_at, expires_at, revoked_at, revoked_reason, metadata_json
		FROM workload_certificates
		WHERE tenant_id = $1
		  AND ($2 = '' OR subject_id = $2)
		ORDER BY issued_at DESC, id DESC
		LIMIT $3
	`, tenantID, subjectID, limit)
	if err != nil {
		return nil, fmt.Errorf("list workload certificates: %w", err)
	}
	defer rows.Close()

	out := make([]models.WorkloadCertificate, 0, limit)
	for rows.Next() {
		item, err := scanWorkloadCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan workload certificate row: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate workload certificate rows: %w", err)
	}

	return out, nil
}

func (s *Store) IssueWorkerCertificateForTenant(ctx context.Context, tenantID string, actor string, request models.IssueWorkerCertificateRequest) (models.IssuedWorkerCertificate, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	workerID := strings.TrimSpace(request.WorkerID)
	if workerID == "" {
		return models.IssuedWorkerCertificate{}, fmt.Errorf("worker_id is required")
	}

	caCert, caSigner, caCertificatePEM, err := s.loadCertificateAuthority()
	if err != nil {
		return models.IssuedWorkerCertificate{}, err
	}

	ttl := s.workloadCertificateTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if request.TTLSeconds > 0 {
		ttl = time.Duration(request.TTLSeconds) * time.Second
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if ttl > 7*24*time.Hour {
		ttl = 7 * 24 * time.Hour
	}

	now := time.Now().UTC()
	notAfter := now.Add(ttl)

	serialRaw, err := randomBytes(16)
	if err != nil {
		return models.IssuedWorkerCertificate{}, fmt.Errorf("generate certificate serial: %w", err)
	}
	serial := new(big.Int).SetBytes(serialRaw)
	if serial.Sign() <= 0 {
		serial = big.NewInt(now.UnixNano())
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return models.IssuedWorkerCertificate{}, fmt.Errorf("generate worker private key: %w", err)
	}

	dnsNames := dedupeNormalizedStrings(request.DNSNames)
	uriSANs, uriSANStrings, err := parseURISANs(request.URISANs)
	if err != nil {
		return models.IssuedWorkerCertificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         workerID,
			Organization:       []string{tenantID},
			OrganizationalUnit: []string{"uss-worker"},
		},
		NotBefore:   now.Add(-1 * time.Minute),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    dnsNames,
		URIs:        uriSANs,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caSigner)
	if err != nil {
		return models.IssuedWorkerCertificate{}, fmt.Errorf("create worker certificate: %w", err)
	}

	certificatePEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}))
	if strings.TrimSpace(certificatePEM) == "" {
		return models.IssuedWorkerCertificate{}, fmt.Errorf("encode worker certificate pem")
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return models.IssuedWorkerCertificate{}, fmt.Errorf("marshal worker private key: %w", err)
	}
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}))
	if strings.TrimSpace(privateKeyPEM) == "" {
		return models.IssuedWorkerCertificate{}, fmt.Errorf("encode worker private key pem")
	}

	fingerprint := sha256.Sum256(der)
	metadata := map[string]any{
		"dns_names": dnsNames,
		"uri_sans":  uriSANStrings,
		"issued_by": actor,
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return models.IssuedWorkerCertificate{}, fmt.Errorf("marshal workload certificate metadata: %w", err)
	}

	item := models.WorkloadCertificate{
		ID:                nextWorkloadCertificateID(),
		TenantID:          tenantID,
		SubjectType:       "worker",
		SubjectID:         workerID,
		SerialNumber:      strings.ToLower(serial.Text(16)),
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		CertificatePEM:    certificatePEM,
		Status:            "active",
		IssuedBy:          actor,
		IssuedAt:          now,
		ExpiresAt:         notAfter,
		Metadata:          metadata,
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO workload_certificates (
			id, tenant_id, subject_type, subject_id, serial_number, fingerprint_sha256,
			certificate_pem, issued_by, status, issued_at, expires_at, revoked_at, revoked_reason, metadata_json
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, NULL, '', $12
		)
	`, item.ID, item.TenantID, item.SubjectType, item.SubjectID, item.SerialNumber, item.FingerprintSHA256, item.CertificatePEM, item.IssuedBy, item.Status, item.IssuedAt, item.ExpiresAt, metadataJSON)
	if err != nil {
		return models.IssuedWorkerCertificate{}, fmt.Errorf("insert workload certificate: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "workload_certificate.issued",
		SourceService: "control-plane",
		AggregateType: "workload_certificate",
		AggregateID:   item.ID,
		Payload: map[string]any{
			"subject_type": item.SubjectType,
			"subject_id":   item.SubjectID,
			"issued_by":    item.IssuedBy,
			"expires_at":   item.ExpiresAt,
		},
		CreatedAt: now,
	})

	return models.IssuedWorkerCertificate{
		Certificate:   item,
		PrivateKeyPEM: privateKeyPEM,
		CABundlePEM:   caCertificatePEM,
	}, nil
}

func (s *Store) RevokeWorkloadCertificateForTenant(ctx context.Context, tenantID string, certificateID string, actor string, reason string) (models.WorkloadCertificate, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	certificateID = strings.TrimSpace(certificateID)
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if actor == "" {
		actor = "system"
	}

	now := time.Now().UTC()
	result, err := s.pool.Exec(ctx, `
		UPDATE workload_certificates
		SET status = 'revoked',
		    revoked_at = $3,
		    revoked_reason = $4
		WHERE tenant_id = $1
		  AND id = $2
		  AND status <> 'revoked'
	`, tenantID, certificateID, now, reason)
	if err != nil {
		return models.WorkloadCertificate{}, false, fmt.Errorf("revoke workload certificate: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		SELECT
			id, tenant_id, subject_type, subject_id, serial_number, fingerprint_sha256,
			certificate_pem, issued_by, status, issued_at, expires_at, revoked_at, revoked_reason, metadata_json
		FROM workload_certificates
		WHERE tenant_id = $1
		  AND id = $2
	`, tenantID, certificateID)
	item, scanErr := scanWorkloadCertificate(row)
	if scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return models.WorkloadCertificate{}, false, nil
		}
		return models.WorkloadCertificate{}, false, fmt.Errorf("load workload certificate: %w", scanErr)
	}

	if result.RowsAffected() > 0 {
		_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
			TenantID:      tenantID,
			EventType:     "workload_certificate.revoked",
			SourceService: "control-plane",
			AggregateType: "workload_certificate",
			AggregateID:   item.ID,
			Payload: map[string]any{
				"subject_type":   item.SubjectType,
				"subject_id":     item.SubjectID,
				"revoked_by":     actor,
				"revoked_reason": reason,
			},
			CreatedAt: now,
		})
	}

	return item, true, nil
}

func (s *Store) loadCertificateAuthority() (*x509.Certificate, crypto.Signer, string, error) {
	certificatePEM := strings.TrimSpace(s.certificateAuthorityCertPEM)
	privateKeyPEM := strings.TrimSpace(s.certificateAuthorityKeyPEM)
	if certificatePEM == "" || privateKeyPEM == "" {
		return nil, nil, "", ErrCertificateAuthorityDisabled
	}

	certBlock, _ := pem.Decode([]byte(certificatePEM))
	if certBlock == nil || len(certBlock.Bytes) == 0 {
		return nil, nil, "", fmt.Errorf("decode ca certificate pem")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse ca certificate pem: %w", err)
	}

	keyBlock, _ := pem.Decode([]byte(privateKeyPEM))
	if keyBlock == nil || len(keyBlock.Bytes) == 0 {
		return nil, nil, "", fmt.Errorf("decode ca private key pem")
	}

	var parsedKey any
	switch keyBlock.Type {
	case "PRIVATE KEY":
		parsedKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("parse pkcs8 ca private key: %w", err)
		}
	case "EC PRIVATE KEY":
		parsedKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("parse ec ca private key: %w", err)
		}
	case "RSA PRIVATE KEY":
		parsedKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("parse rsa ca private key: %w", err)
		}
	default:
		parsedKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("parse ca private key: %w", err)
		}
	}

	signer, ok := parsedKey.(crypto.Signer)
	if !ok {
		return nil, nil, "", fmt.Errorf("ca private key does not implement signer")
	}

	return certificate, signer, certificatePEM, nil
}

func parseURISANs(values []string) ([]*url.URL, []string, error) {
	seen := make(map[string]struct{}, len(values))
	parsed := make([]*url.URL, 0, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		uri, err := url.Parse(trimmed)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid uri_san %q: %w", trimmed, err)
		}
		if uri.Scheme == "" || uri.Host == "" {
			return nil, nil, fmt.Errorf("invalid uri_san %q: scheme and host are required", trimmed)
		}
		canonical := strings.ToLower(trimmed)
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		parsed = append(parsed, uri)
		out = append(out, trimmed)
	}
	return parsed, out, nil
}

func dedupeNormalizedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func scanWorkloadCertificate(row interface{ Scan(dest ...any) error }) (models.WorkloadCertificate, error) {
	var (
		item         models.WorkloadCertificate
		metadataJSON []byte
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.SubjectType,
		&item.SubjectID,
		&item.SerialNumber,
		&item.FingerprintSHA256,
		&item.CertificatePEM,
		&item.IssuedBy,
		&item.Status,
		&item.IssuedAt,
		&item.ExpiresAt,
		&item.RevokedAt,
		&item.RevokedReason,
		&metadataJSON,
	)
	if err != nil {
		return models.WorkloadCertificate{}, err
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &item.Metadata); err != nil {
			return models.WorkloadCertificate{}, fmt.Errorf("decode workload certificate metadata: %w", err)
		}
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}

	return item, nil
}

func nextWorkloadCertificateID() string {
	sequence := atomic.AddUint64(&workloadCertificateSequence, 1)
	return fmt.Sprintf("workload-cert-%d-%06d", time.Now().UTC().Unix(), sequence)
}
