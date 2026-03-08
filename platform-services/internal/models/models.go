package models

import "time"

const (
	ConnectorKindWebhook    = "webhook"
	ConnectorKindJira       = "jira"
	ConnectorKindServiceNow = "servicenow"
	ConnectorKindSIEM       = "siem"
	ConnectorKindCMDB       = "cmdb"
	ConnectorKindSlack      = "slack"
	ConnectorKindTeams      = "teams"

	JobKindConnectorDispatch    = "connector.dispatch"
	JobKindNotificationDispatch = "notification.dispatch"
	JobKindAuditExportExecute   = "audit_export.execute"
	JobKindFeedSync             = "feed.sync"
	JobKindJiraIssueUpsert      = "jira.issue.upsert"
	JobKindServiceNowIncident   = "servicenow.incident.upsert"
	JobKindSIEMEventPush        = "siem.event.push"
	JobKindCMDBAssetUpsert      = "cmdb.asset.upsert"

	JobStatusQueued     = "queued"
	JobStatusRetrying   = "retrying"
	JobStatusRunning    = "running"
	JobStatusSucceeded  = "succeeded"
	JobStatusDeadLetter = "dead_letter"

	NotificationStatusQueued       = "queued"
	NotificationStatusSent         = "sent"
	NotificationStatusFailed       = "failed"
	NotificationStatusAcknowledged = "acknowledged"

	AuditExportStatusQueued    = "queued"
	AuditExportStatusCompleted = "completed"
	AuditExportStatusFailed    = "failed"

	SyncStatusQueued    = "queued"
	SyncStatusCompleted = "completed"
	SyncStatusFailed    = "failed"
)

type Connector struct {
	ID                    string            `json:"id"`
	TenantID              string            `json:"tenant_id"`
	Name                  string            `json:"name"`
	ConnectorKind         string            `json:"connector_kind"`
	EndpointURL           string            `json:"endpoint_url"`
	AuthType              string            `json:"auth_type"`
	AuthSecretRef         string            `json:"auth_secret_ref,omitempty"`
	DefaultHeaders        map[string]string `json:"default_headers,omitempty"`
	Metadata              map[string]any    `json:"metadata,omitempty"`
	Enabled               bool              `json:"enabled"`
	RetryMaxAttempts      int               `json:"retry_max_attempts"`
	RetryBaseDelaySeconds int               `json:"retry_base_delay_seconds"`
	RetryMaxDelaySeconds  int               `json:"retry_max_delay_seconds"`
	CreatedBy             string            `json:"created_by,omitempty"`
	UpdatedBy             string            `json:"updated_by,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

type CreateConnectorRequest struct {
	Name                  string            `json:"name"`
	ConnectorKind         string            `json:"connector_kind"`
	EndpointURL           string            `json:"endpoint_url"`
	AuthType              string            `json:"auth_type"`
	AuthSecretRef         string            `json:"auth_secret_ref"`
	DefaultHeaders        map[string]string `json:"default_headers"`
	Metadata              map[string]any    `json:"metadata"`
	Enabled               *bool             `json:"enabled"`
	RetryMaxAttempts      int               `json:"retry_max_attempts"`
	RetryBaseDelaySeconds int               `json:"retry_base_delay_seconds"`
	RetryMaxDelaySeconds  int               `json:"retry_max_delay_seconds"`
}

type UpdateConnectorRequest struct {
	Name                  string            `json:"name"`
	EndpointURL           string            `json:"endpoint_url"`
	AuthType              string            `json:"auth_type"`
	AuthSecretRef         string            `json:"auth_secret_ref"`
	DefaultHeaders        map[string]string `json:"default_headers"`
	Metadata              map[string]any    `json:"metadata"`
	Enabled               *bool             `json:"enabled"`
	RetryMaxAttempts      int               `json:"retry_max_attempts"`
	RetryBaseDelaySeconds int               `json:"retry_base_delay_seconds"`
	RetryMaxDelaySeconds  int               `json:"retry_max_delay_seconds"`
}

type PlatformJob struct {
	ID                 string         `json:"id"`
	TenantID           string         `json:"tenant_id"`
	JobKind            string         `json:"job_kind"`
	ConnectorID        string         `json:"connector_id,omitempty"`
	Payload            map[string]any `json:"payload,omitempty"`
	Status             string         `json:"status"`
	AttemptCount       int            `json:"attempt_count"`
	NextAttemptAt      time.Time      `json:"next_attempt_at"`
	LastError          string         `json:"last_error,omitempty"`
	LastResponseStatus int            `json:"last_response_status,omitempty"`
	LastResponseBody   string         `json:"last_response_body,omitempty"`
	LeasedBy           string         `json:"leased_by,omitempty"`
	LeaseExpiresAt     *time.Time     `json:"lease_expires_at,omitempty"`
	CreatedBy          string         `json:"created_by,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
	CompletedAt        *time.Time     `json:"completed_at,omitempty"`
	Connector          *Connector     `json:"connector,omitempty"`
}

type EnqueuePlatformJobRequest struct {
	JobKind     string         `json:"job_kind"`
	ConnectorID string         `json:"connector_id"`
	Payload     map[string]any `json:"payload"`
	NotBefore   *time.Time     `json:"not_before,omitempty"`
}

type FinalizePlatformJobRequest struct {
	JobID          string `json:"job_id"`
	Success        bool   `json:"success"`
	ResponseStatus int    `json:"response_status"`
	ResponseBody   string `json:"response_body"`
	ErrorMessage   string `json:"error_message"`
	DurationMs     int64  `json:"duration_ms"`
}

type Notification struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	Severity       string         `json:"severity"`
	Title          string         `json:"title"`
	Body           string         `json:"body"`
	Status         string         `json:"status"`
	OwnerTeam      string         `json:"owner_team,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	CreatedBy      string         `json:"created_by,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	AcknowledgedAt *time.Time     `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string         `json:"acknowledged_by,omitempty"`
}

type CreateNotificationRequest struct {
	Severity    string         `json:"severity"`
	Title       string         `json:"title"`
	Body        string         `json:"body"`
	OwnerTeam   string         `json:"owner_team"`
	Channel     string         `json:"channel"`
	ConnectorID string         `json:"connector_id"`
	Metadata    map[string]any `json:"metadata"`
}

type AuditExport struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	Format         string         `json:"format"`
	DestinationRef string         `json:"destination_ref"`
	Filters        map[string]any `json:"filters,omitempty"`
	Status         string         `json:"status"`
	RequestedBy    string         `json:"requested_by,omitempty"`
	RequestedAt    time.Time      `json:"requested_at"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
	FileRef        string         `json:"file_ref,omitempty"`
	ErrorMessage   string         `json:"error_message,omitempty"`
}

type CreateAuditExportRequest struct {
	Format         string         `json:"format"`
	DestinationRef string         `json:"destination_ref"`
	ConnectorID    string         `json:"connector_id"`
	Filters        map[string]any `json:"filters"`
}

type SyncRun struct {
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id"`
	SyncKind     string         `json:"sync_kind"`
	SourceRef    string         `json:"source_ref"`
	VersionTag   string         `json:"version_tag"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	Status       string         `json:"status"`
	StartedBy    string         `json:"started_by,omitempty"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
	Summary      map[string]any `json:"summary,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
}

type CreateSyncRunRequest struct {
	SyncKind    string         `json:"sync_kind"`
	SourceRef   string         `json:"source_ref"`
	VersionTag  string         `json:"version_tag"`
	ConnectorID string         `json:"connector_id"`
	Metadata    map[string]any `json:"metadata"`
}

type QueueStat struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

type PlatformMetrics struct {
	QueueStats           []QueueStat `json:"queue_stats"`
	NotificationsOpen    int64       `json:"notifications_open"`
	AuditExportsPending  int64       `json:"audit_exports_pending"`
	SyncRunsPending      int64       `json:"sync_runs_pending"`
	ConnectorCount       int64       `json:"connector_count"`
	TimestampUnixSeconds int64       `json:"timestamp_unix_seconds"`
}
