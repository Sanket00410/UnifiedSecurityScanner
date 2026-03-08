package store

import (
	"fmt"
	"strings"
	"time"

	"unifiedsecurityscanner/platform-services/internal/models"
)

func scanConnector(scanner rowScanner) (models.Connector, error) {
	var (
		item               models.Connector
		defaultHeadersJSON []byte
		metadataJSON       []byte
	)
	if err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.Name,
		&item.ConnectorKind,
		&item.EndpointURL,
		&item.AuthType,
		&item.AuthSecretRef,
		&defaultHeadersJSON,
		&metadataJSON,
		&item.Enabled,
		&item.RetryMaxAttempts,
		&item.RetryBaseDelaySeconds,
		&item.RetryMaxDelaySeconds,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return models.Connector{}, fmt.Errorf("scan connector: %w", err)
	}
	item.DefaultHeaders = parseStringMap(defaultHeadersJSON)
	item.Metadata = parseJSONMapBytes(metadataJSON)
	return item, nil
}

func scanJob(scanner rowScanner) (models.PlatformJob, error) {
	var (
		item        models.PlatformJob
		connectorID *string
		payloadJSON []byte
		leaseExpiry *time.Time
		completedAt *time.Time
	)
	if err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.JobKind,
		&connectorID,
		&payloadJSON,
		&item.Status,
		&item.AttemptCount,
		&item.NextAttemptAt,
		&item.LastError,
		&item.LastResponseStatus,
		&item.LastResponseBody,
		&item.LeasedBy,
		&leaseExpiry,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&completedAt,
	); err != nil {
		return models.PlatformJob{}, fmt.Errorf("scan platform job: %w", err)
	}
	if connectorID != nil {
		item.ConnectorID = strings.TrimSpace(*connectorID)
	}
	item.Payload = parseJSONMapBytes(payloadJSON)
	item.LeaseExpiresAt = leaseExpiry
	item.CompletedAt = completedAt
	return item, nil
}

func scanNotification(scanner rowScanner) (models.Notification, error) {
	var (
		item         models.Notification
		metadataJSON []byte
	)
	if err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.Severity,
		&item.Title,
		&item.Body,
		&item.Status,
		&item.OwnerTeam,
		&metadataJSON,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.AcknowledgedAt,
		&item.AcknowledgedBy,
	); err != nil {
		return models.Notification{}, fmt.Errorf("scan notification: %w", err)
	}
	item.Metadata = parseJSONMapBytes(metadataJSON)
	return item, nil
}

func scanAuditExport(scanner rowScanner) (models.AuditExport, error) {
	var (
		item        models.AuditExport
		filtersJSON []byte
	)
	if err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.Format,
		&item.DestinationRef,
		&filtersJSON,
		&item.Status,
		&item.RequestedBy,
		&item.RequestedAt,
		&item.CompletedAt,
		&item.FileRef,
		&item.ErrorMessage,
	); err != nil {
		return models.AuditExport{}, fmt.Errorf("scan audit export: %w", err)
	}
	item.Filters = parseJSONMapBytes(filtersJSON)
	return item, nil
}

func scanSyncRun(scanner rowScanner) (models.SyncRun, error) {
	var (
		item         models.SyncRun
		metadataJSON []byte
		summaryJSON  []byte
	)
	if err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.SyncKind,
		&item.SourceRef,
		&item.VersionTag,
		&metadataJSON,
		&item.Status,
		&item.StartedBy,
		&item.StartedAt,
		&item.CompletedAt,
		&summaryJSON,
		&item.ErrorMessage,
	); err != nil {
		return models.SyncRun{}, fmt.Errorf("scan sync run: %w", err)
	}
	item.Metadata = parseJSONMapBytes(metadataJSON)
	item.Summary = parseJSONMapBytes(summaryJSON)
	return item, nil
}
