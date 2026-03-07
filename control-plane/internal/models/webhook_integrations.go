package models

import "time"

type WebhookIntegration struct {
	ID            string            `json:"id"`
	TenantID      string            `json:"tenant_id,omitempty"`
	Name          string            `json:"name"`
	EndpointURL   string            `json:"endpoint_url"`
	EventTypes    []string          `json:"event_types,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Status        string            `json:"status"`
	SecretSet     bool              `json:"secret_set"`
	LastAttemptAt *time.Time        `json:"last_attempt_at,omitempty"`
	LastSuccessAt *time.Time        `json:"last_success_at,omitempty"`
	CreatedBy     string            `json:"created_by,omitempty"`
	UpdatedBy     string            `json:"updated_by,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type CreateWebhookIntegrationRequest struct {
	Name        string            `json:"name"`
	EndpointURL string            `json:"endpoint_url"`
	EventTypes  []string          `json:"event_types"`
	Headers     map[string]string `json:"headers"`
	Status      string            `json:"status"`
	Secret      string            `json:"secret"`
}

type UpdateWebhookIntegrationRequest struct {
	Name        string            `json:"name"`
	EndpointURL string            `json:"endpoint_url"`
	EventTypes  []string          `json:"event_types"`
	Headers     map[string]string `json:"headers"`
	Status      string            `json:"status"`
	Secret      string            `json:"secret"`
}

type WebhookDelivery struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id,omitempty"`
	WebhookID       string     `json:"webhook_id"`
	PlatformEventID string     `json:"platform_event_id"`
	EventType       string     `json:"event_type"`
	Status          string     `json:"status"`
	AttemptCount    int        `json:"attempt_count"`
	ResponseStatus  int        `json:"response_status,omitempty"`
	ResponseBody    string     `json:"response_body,omitempty"`
	ErrorMessage    string     `json:"error_message,omitempty"`
	AttemptedAt     time.Time  `json:"attempted_at"`
	NextAttemptAt   *time.Time `json:"next_attempt_at,omitempty"`
	DeliveredAt     *time.Time `json:"delivered_at,omitempty"`
	DeadLetteredAt  *time.Time `json:"dead_lettered_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

type DispatchWebhookDeliveriesRequest struct {
	WebhookID string `json:"webhook_id"`
	EventType string `json:"event_type"`
	Limit     int    `json:"limit"`
	Replay    bool   `json:"replay"`
}

type DispatchWebhookDeliveriesResult struct {
	Attempted int64            `json:"attempted"`
	Delivered int64            `json:"delivered"`
	Failed    int64            `json:"failed"`
	Skipped   int64            `json:"skipped"`
	ByWebhook map[string]int64 `json:"by_webhook"`
}

type DispatchWebhookDeliveriesSweepResult struct {
	TenantsEvaluated int64                            `json:"tenants_evaluated"`
	Attempted        int64                            `json:"attempted"`
	Delivered        int64                            `json:"delivered"`
	Failed           int64                            `json:"failed"`
	Skipped          int64                            `json:"skipped"`
	ByTenant         map[string]DispatchTenantSummary `json:"by_tenant"`
}

type DispatchTenantSummary struct {
	Attempted int64 `json:"attempted"`
	Delivered int64 `json:"delivered"`
	Failed    int64 `json:"failed"`
	Skipped   int64 `json:"skipped"`
}
