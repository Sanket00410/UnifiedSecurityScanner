package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"unifiedsecurityscanner/platform-services/internal/config"
	"unifiedsecurityscanner/platform-services/internal/models"
)

const maxConnectorResponseBytes = 32_768

type workerStore interface {
	LeaseJobs(ctx context.Context, workerID string, leaseTTL time.Duration, batch int) ([]models.PlatformJob, error)
	FinalizeJob(ctx context.Context, workerID string, request models.FinalizePlatformJobRequest) (models.PlatformJob, bool, error)
	GetAuditExport(ctx context.Context, tenantID string, exportID string) (models.AuditExport, bool, error)
	ListAuditExportEvents(ctx context.Context, tenantID string, filters map[string]any, limit int) ([]map[string]any, error)
}

type Runner struct {
	cfg    config.Config
	store  workerStore
	logger *log.Logger
	client *http.Client
}

type executionResult struct {
	success        bool
	responseStatus int
	responseBody   string
	errorMessage   string
}

func New(cfg config.Config, dataStore workerStore, logger *log.Logger) *Runner {
	if logger == nil {
		logger = log.New(os.Stdout, "platform-worker ", log.LstdFlags|log.LUTC)
	}
	timeout := cfg.HTTPClientTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Runner{
		cfg:    cfg,
		store:  dataStore,
		logger: logger,
		client: &http.Client{Timeout: timeout},
	}
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.RunOnce(ctx); err != nil {
		r.logger.Printf("initial worker cycle failed: %v", err)
	}

	interval := r.cfg.WorkerInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.RunOnce(ctx); err != nil {
				r.logger.Printf("worker cycle failed: %v", err)
			}
		}
	}
}

func (r *Runner) RunOnce(ctx context.Context) error {
	jobs, err := r.store.LeaseJobs(ctx, r.cfg.WorkerID, r.cfg.WorkerLeaseTTL, r.cfg.WorkerBatchSize)
	if err != nil {
		return err
	}
	if len(jobs) == 0 {
		return nil
	}

	for _, job := range jobs {
		started := time.Now().UTC()
		result := r.executeJob(ctx, job)
		durationMs := time.Since(started).Milliseconds()
		_, _, finalizeErr := r.store.FinalizeJob(ctx, r.cfg.WorkerID, models.FinalizePlatformJobRequest{
			JobID:          job.ID,
			Success:        result.success,
			ResponseStatus: result.responseStatus,
			ResponseBody:   result.responseBody,
			ErrorMessage:   result.errorMessage,
			DurationMs:     durationMs,
		})
		if finalizeErr != nil {
			r.logger.Printf("finalize job %s failed: %v", job.ID, finalizeErr)
			continue
		}
		if !result.success {
			r.logger.Printf("job %s failed: %s", job.ID, result.errorMessage)
		}
	}

	return nil
}

func (r *Runner) executeJob(ctx context.Context, job models.PlatformJob) executionResult {
	switch strings.TrimSpace(job.JobKind) {
	case models.JobKindNotificationDispatch:
		return r.executeNotification(ctx, job)
	case models.JobKindAuditExportExecute:
		return r.executeAuditExport(ctx, job)
	case models.JobKindFeedSync:
		return r.executeFeedSync(ctx, job)
	case models.JobKindJiraIssueUpsert, models.JobKindServiceNowIncident, models.JobKindSIEMEventPush, models.JobKindCMDBAssetUpsert, models.JobKindConnectorDispatch:
		return r.executeConnectorDispatch(ctx, job, job.Payload)
	default:
		if job.Connector != nil {
			return r.executeConnectorDispatch(ctx, job, job.Payload)
		}
		return executionResult{
			success:      false,
			errorMessage: fmt.Sprintf("unsupported job kind %q", job.JobKind),
		}
	}
}

func (r *Runner) executeNotification(ctx context.Context, job models.PlatformJob) executionResult {
	payload := cloneMap(job.Payload)
	if job.Connector == nil {
		return successResult(http.StatusAccepted, map[string]any{
			"delivery": "queued_without_external_connector",
			"title":    extractString(payload, "title"),
			"channel":  extractString(payload, "channel"),
		})
	}
	return r.executeConnectorDispatch(ctx, job, payload)
}

func (r *Runner) executeAuditExport(ctx context.Context, job models.PlatformJob) executionResult {
	payload := cloneMap(job.Payload)
	exportID := extractString(payload, "audit_export_id")
	if exportID == "" {
		return executionResult{success: false, errorMessage: "audit_export_id is required"}
	}

	exportRecord, found, err := r.store.GetAuditExport(ctx, job.TenantID, exportID)
	if err != nil {
		return executionResult{success: false, errorMessage: fmt.Sprintf("load audit export: %v", err)}
	}
	if !found {
		return executionResult{success: false, errorMessage: "audit export not found"}
	}

	rows, err := r.store.ListAuditExportEvents(ctx, job.TenantID, exportRecord.Filters, 5000)
	if err != nil {
		return executionResult{success: false, errorMessage: fmt.Sprintf("load audit events: %v", err)}
	}

	exportPath, writeErr := r.writeAuditExportFile(job.TenantID, exportRecord, rows)
	if writeErr != nil {
		return executionResult{success: false, errorMessage: writeErr.Error()}
	}

	response := map[string]any{
		"file_ref":          exportPath,
		"records_exported":  len(rows),
		"destination_ref":   exportRecord.DestinationRef,
		"generated_at_utc":  time.Now().UTC().Format(time.RFC3339),
		"audit_export_id":   exportID,
		"connector_applied": job.Connector != nil,
	}

	if job.Connector != nil {
		connectorPayload := map[string]any{
			"audit_export_id":  exportID,
			"file_ref":         exportPath,
			"records_exported": len(rows),
			"format":           exportRecord.Format,
			"destination_ref":  exportRecord.DestinationRef,
		}
		connectorResult := r.executeConnectorDispatch(ctx, job, connectorPayload)
		if !connectorResult.success {
			return connectorResult
		}
		response["connector_response_status"] = connectorResult.responseStatus
	}

	return successResult(http.StatusOK, response)
}

func (r *Runner) writeAuditExportFile(tenantID string, exportRecord models.AuditExport, rows []map[string]any) (string, error) {
	root := strings.TrimSpace(r.cfg.ExportRoot)
	if root == "" {
		root = "./exports"
	}
	tenantRoot := filepath.Join(root, sanitizePath(tenantID))
	if err := os.MkdirAll(tenantRoot, 0o755); err != nil {
		return "", fmt.Errorf("create export dir: %w", err)
	}

	fileExt := ".jsonl"
	if strings.EqualFold(exportRecord.Format, "json") {
		fileExt = ".json"
	}
	filePath := filepath.Join(tenantRoot, fmt.Sprintf("%s-%d%s", sanitizePath(exportRecord.ID), time.Now().UTC().Unix(), fileExt))

	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("create export file: %w", err)
	}
	defer file.Close()

	if strings.EqualFold(exportRecord.Format, "json") {
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(rows); err != nil {
			return "", fmt.Errorf("write json export: %w", err)
		}
		return filePath, nil
	}

	writer := bufio.NewWriter(file)
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			return "", fmt.Errorf("marshal export row: %w", err)
		}
		if _, err := writer.Write(encoded); err != nil {
			return "", fmt.Errorf("write export row: %w", err)
		}
		if err := writer.WriteByte('\n'); err != nil {
			return "", fmt.Errorf("write export newline: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return "", fmt.Errorf("flush export file: %w", err)
	}
	return filePath, nil
}

func (r *Runner) executeFeedSync(ctx context.Context, job models.PlatformJob) executionResult {
	payload := cloneMap(job.Payload)
	if extractString(payload, "sync_run_id") == "" {
		return executionResult{success: false, errorMessage: "sync_run_id is required"}
	}

	summary := map[string]any{
		"sync_run_id": extractString(payload, "sync_run_id"),
		"sync_kind":   extractString(payload, "sync_kind"),
		"source_ref":  extractString(payload, "source_ref"),
		"version_tag": extractString(payload, "version_tag"),
		"synced_at":   time.Now().UTC().Format(time.RFC3339),
	}

	if job.Connector == nil {
		summary["mode"] = "local"
		summary["items_synced"] = 1
		return successResult(http.StatusOK, summary)
	}

	connectorPayload := map[string]any{
		"action":     "feed.sync",
		"sync_kind":  summary["sync_kind"],
		"source_ref": summary["source_ref"],
		"version":    summary["version_tag"],
		"metadata":   payload["metadata"],
	}
	connectorResult := r.executeConnectorDispatch(ctx, job, connectorPayload)
	if !connectorResult.success {
		return connectorResult
	}

	summary["mode"] = "connector"
	summary["connector_status"] = connectorResult.responseStatus
	summary["items_synced"] = 1
	return successResult(http.StatusOK, summary)
}

func (r *Runner) executeConnectorDispatch(ctx context.Context, job models.PlatformJob, payload map[string]any) executionResult {
	connector := job.Connector
	if connector == nil {
		return executionResult{success: false, errorMessage: "connector is required for connector dispatch"}
	}
	if !connector.Enabled {
		return executionResult{success: false, errorMessage: "connector is disabled"}
	}

	endpoint := strings.TrimSpace(connector.EndpointURL)
	if endpoint == "" {
		return executionResult{success: false, errorMessage: "connector endpoint is empty"}
	}

	method := strings.ToUpper(extractString(connector.Metadata, "method"))
	if method == "" {
		method = http.MethodPost
	}

	requestBody := connectorPayloadForJob(job, payload)
	encodedBody, err := json.Marshal(requestBody)
	if err != nil {
		return executionResult{success: false, errorMessage: fmt.Sprintf("marshal connector payload: %v", err)}
	}

	reqCtx, cancel := context.WithTimeout(ctx, r.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, endpoint, bytes.NewReader(encodedBody))
	if err != nil {
		return executionResult{success: false, errorMessage: fmt.Sprintf("build connector request: %v", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range connector.DefaultHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		req.Header.Set(key, value)
	}
	applyConnectorAuth(req, *connector)

	resp, err := r.client.Do(req)
	if err != nil {
		return executionResult{success: false, errorMessage: fmt.Sprintf("connector request failed: %v", err)}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxConnectorResponseBytes))
	body := strings.TrimSpace(string(bodyBytes))
	if body == "" {
		body = "{}"
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return executionResult{
			success:        true,
			responseStatus: resp.StatusCode,
			responseBody:   body,
		}
	}
	return executionResult{
		success:        false,
		responseStatus: resp.StatusCode,
		responseBody:   body,
		errorMessage:   fmt.Sprintf("connector returned status %d", resp.StatusCode),
	}
}

func connectorPayloadForJob(job models.PlatformJob, payload map[string]any) map[string]any {
	connector := job.Connector
	if connector == nil {
		return cloneMap(payload)
	}
	switch connector.ConnectorKind {
	case models.ConnectorKindJira:
		return map[string]any{
			"fields": map[string]any{
				"summary":     firstNonEmpty(extractString(payload, "summary"), extractString(payload, "title"), "USS finding"),
				"description": firstNonEmpty(extractString(payload, "description"), extractString(payload, "body"), "Generated by unified security scanner"),
				"project": map[string]any{
					"key": firstNonEmpty(extractString(payload, "project_key"), extractString(connector.Metadata, "project_key"), "USS"),
				},
				"issuetype": map[string]any{
					"name": firstNonEmpty(extractString(payload, "issue_type"), extractString(connector.Metadata, "issue_type"), "Task"),
				},
				"labels": []string{"uss", sanitizePath(job.JobKind)},
			},
		}
	case models.ConnectorKindServiceNow:
		return map[string]any{
			"short_description": firstNonEmpty(extractString(payload, "summary"), extractString(payload, "title"), "USS incident"),
			"description":       firstNonEmpty(extractString(payload, "description"), extractString(payload, "body"), "Generated by unified security scanner"),
			"severity":          firstNonEmpty(extractString(payload, "severity"), "3"),
			"u_source":          "unified_security_scanner",
		}
	case models.ConnectorKindSIEM:
		return map[string]any{
			"event_type": firstNonEmpty(extractString(payload, "event_type"), job.JobKind),
			"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
			"tenant_id":  job.TenantID,
			"payload":    cloneMap(payload),
		}
	case models.ConnectorKindCMDB:
		return map[string]any{
			"asset_id":    firstNonEmpty(extractString(payload, "asset_id"), extractString(payload, "resource_id"), "unknown"),
			"name":        firstNonEmpty(extractString(payload, "name"), extractString(payload, "title"), "USS Asset"),
			"owner_team":  extractString(payload, "owner_team"),
			"criticality": extractString(payload, "criticality"),
			"attributes":  cloneMap(payload),
		}
	default:
		return cloneMap(payload)
	}
}

func applyConnectorAuth(req *http.Request, connector models.Connector) {
	authType := strings.ToLower(strings.TrimSpace(connector.AuthType))
	secret := strings.TrimSpace(connector.AuthSecretRef)
	if secret == "" {
		return
	}
	switch authType {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+secret)
	case "basic":
		parts := strings.SplitN(secret, ":", 2)
		if len(parts) == 2 {
			token := base64.StdEncoding.EncodeToString([]byte(parts[0] + ":" + parts[1]))
			req.Header.Set("Authorization", "Basic "+token)
		}
	case "header":
		if strings.Contains(secret, ":") {
			parts := strings.SplitN(secret, ":", 2)
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		} else if strings.Contains(secret, "=") {
			parts := strings.SplitN(secret, "=", 2)
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

func successResult(status int, payload map[string]any) executionResult {
	encoded, err := json.Marshal(payload)
	if err != nil {
		encoded = []byte(`{"status":"ok"}`)
	}
	return executionResult{
		success:        true,
		responseStatus: status,
		responseBody:   string(encoded),
	}
}

func cloneMap(payload map[string]any) map[string]any {
	if payload == nil {
		return map[string]any{}
	}
	result := make(map[string]any, len(payload))
	for key, value := range payload {
		result[key] = value
	}
	return result
}

func extractString(payload map[string]any, key string) string {
	if payload == nil {
		return ""
	}
	raw, ok := payload[key]
	if !ok || raw == nil {
		return ""
	}
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sanitizePath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(
		"..", "",
		"/", "-",
		"\\", "-",
		":", "-",
		" ", "-",
		"\t", "-",
		"\n", "-",
	)
	safe := replacer.Replace(trimmed)
	if safe == "" {
		return "unknown"
	}
	return safe
}
