package auth

import (
	"context"
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
	"time"
)

const WorkerIdentityAudience = "worker-control-plane"

const workerIdentityIssuer = "uss-control-plane"

const maxWorkerIdentityTTL = 24 * time.Hour

var (
	ErrWorkerIdentityDisabled  = errors.New("worker identity signing key is not configured")
	ErrInvalidWorkerIdentity   = errors.New("invalid worker identity token")
	ErrExpiredWorkerIdentity   = errors.New("expired worker identity token")
	ErrInvalidWorkerIdentifier = errors.New("worker identity subject is invalid")
)

type WorkerIdentityClaims struct {
	TokenID   string `json:"jti"`
	WorkerID  string `json:"sub"`
	TenantID  string `json:"tenant_id,omitempty"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

const workerIdentityClaimsContextKey contextKey = "auth.worker_identity"

func WithWorkerIdentityClaims(ctx context.Context, claims WorkerIdentityClaims) context.Context {
	return context.WithValue(ctx, workerIdentityClaimsContextKey, claims)
}

func WorkerIdentityClaimsFromContext(ctx context.Context) (WorkerIdentityClaims, bool) {
	claims, ok := ctx.Value(workerIdentityClaimsContextKey).(WorkerIdentityClaims)
	return claims, ok
}

func IssueWorkerIdentityToken(signingKey string, workerID string, tenantID string, ttl time.Duration, now time.Time) (string, WorkerIdentityClaims, error) {
	signingKey = strings.TrimSpace(signingKey)
	if signingKey == "" {
		return "", WorkerIdentityClaims{}, ErrWorkerIdentityDisabled
	}

	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return "", WorkerIdentityClaims{}, ErrInvalidWorkerIdentifier
	}

	if ttl <= 0 {
		ttl = time.Hour
	}
	if ttl > maxWorkerIdentityTTL {
		ttl = maxWorkerIdentityTTL
	}

	now = now.UTC()
	tokenID, err := randomTokenID()
	if err != nil {
		return "", WorkerIdentityClaims{}, fmt.Errorf("generate worker identity token id: %w", err)
	}

	claims := WorkerIdentityClaims{
		TokenID:   tokenID,
		WorkerID:  workerID,
		TenantID:  strings.TrimSpace(tenantID),
		Issuer:    workerIdentityIssuer,
		Audience:  WorkerIdentityAudience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", WorkerIdentityClaims{}, fmt.Errorf("marshal worker identity claims: %w", err)
	}

	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	signature := signWorkerIdentity(signingKey, payloadPart)
	signaturePart := base64.RawURLEncoding.EncodeToString(signature)

	return payloadPart + "." + signaturePart, claims, nil
}

func ValidateWorkerIdentityToken(signingKey string, token string, now time.Time) (WorkerIdentityClaims, error) {
	signingKey = strings.TrimSpace(signingKey)
	if signingKey == "" {
		return WorkerIdentityClaims{}, ErrWorkerIdentityDisabled
	}

	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return WorkerIdentityClaims{}, ErrInvalidWorkerIdentity
	}

	payloadPart := strings.TrimSpace(parts[0])
	signaturePart := strings.TrimSpace(parts[1])
	if payloadPart == "" || signaturePart == "" {
		return WorkerIdentityClaims{}, ErrInvalidWorkerIdentity
	}

	expectedSignature := signWorkerIdentity(signingKey, payloadPart)
	actualSignature, err := base64.RawURLEncoding.DecodeString(signaturePart)
	if err != nil {
		return WorkerIdentityClaims{}, ErrInvalidWorkerIdentity
	}
	if subtle.ConstantTimeCompare(actualSignature, expectedSignature) != 1 {
		return WorkerIdentityClaims{}, ErrInvalidWorkerIdentity
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return WorkerIdentityClaims{}, ErrInvalidWorkerIdentity
	}

	var claims WorkerIdentityClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return WorkerIdentityClaims{}, ErrInvalidWorkerIdentity
	}

	if strings.TrimSpace(claims.WorkerID) == "" {
		return WorkerIdentityClaims{}, ErrInvalidWorkerIdentifier
	}
	if strings.TrimSpace(claims.Audience) != WorkerIdentityAudience || strings.TrimSpace(claims.Issuer) != workerIdentityIssuer {
		return WorkerIdentityClaims{}, ErrInvalidWorkerIdentity
	}

	nowUnix := now.UTC().Unix()
	if claims.ExpiresAt <= nowUnix {
		return WorkerIdentityClaims{}, ErrExpiredWorkerIdentity
	}
	if claims.IssuedAt > nowUnix+300 {
		return WorkerIdentityClaims{}, ErrInvalidWorkerIdentity
	}

	return claims, nil
}

func signWorkerIdentity(signingKey string, payloadPart string) []byte {
	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write([]byte(payloadPart))
	return mac.Sum(nil)
}

func randomTokenID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
