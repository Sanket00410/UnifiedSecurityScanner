package models

import "time"

type IssueWorkerIdentityRequest struct {
	WorkerID   string `json:"worker_id"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

type IssuedWorkerIdentityToken struct {
	Token      string    `json:"token"`
	TokenType  string    `json:"token_type"`
	TokenID    string    `json:"token_id"`
	WorkerID   string    `json:"worker_id"`
	TenantID   string    `json:"tenant_id,omitempty"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	TTLSeconds int64     `json:"ttl_seconds"`
	Audience   string    `json:"audience"`
}
