package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"unifiedsecurityscanner/platform-services/internal/models"
)

type rowScanner interface {
	Scan(dest ...any) error
}

func normalizeLimit(limit int, fallback int) int {
	return clampInt(limit, 1, maxListLimit, fallback)
}

func clampInt(value int, min int, max int, fallback int) int {
	if value == 0 {
		value = fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func normalizeActor(raw string) string {
	if actor := strings.TrimSpace(raw); actor != "" {
		return actor
	}
	return "platform-services"
}

func normalizeConnectorKind(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func normalizeJobKind(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func normalizeSyncKind(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func normalizeStatus(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func normalizeSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "info"
	}
}

func normalizeChannel(raw string) string {
	channel := strings.ToLower(strings.TrimSpace(raw))
	if channel == "" {
		return "webhook"
	}
	return channel
}

func normalizeExportFormat(raw string) string {
	format := strings.ToLower(strings.TrimSpace(raw))
	switch format {
	case "json", "jsonl":
		return format
	default:
		return "jsonl"
	}
}

func normalizeAuthType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "bearer", "basic", "header":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "none"
	}
}

func isSupportedConnectorKind(kind string) bool {
	switch kind {
	case models.ConnectorKindWebhook,
		models.ConnectorKindJira,
		models.ConnectorKindServiceNow,
		models.ConnectorKindSIEM,
		models.ConnectorKindCMDB,
		models.ConnectorKindSlack,
		models.ConnectorKindTeams:
		return true
	default:
		return false
	}
}

func marshalAnyMap(value map[string]any) []byte {
	normalized := cloneAnyMap(value)
	if normalized == nil {
		normalized = map[string]any{}
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return []byte("{}")
	}
	return payload
}

func marshalStringMap(value map[string]string) []byte {
	normalized := cloneStringMap(value)
	if normalized == nil {
		normalized = map[string]string{}
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return []byte("{}")
	}
	return payload
}

func parseJSONMap(raw string) map[string]any {
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil || parsed == nil {
		return map[string]any{}
	}
	return parsed
}

func parseJSONMapBytes(raw []byte) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed == nil {
		return map[string]any{}
	}
	return parsed
}

func parseStringMap(raw []byte) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	var parsed map[string]string
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed == nil {
		return map[string]string{}
	}
	return parsed
}

func cloneAnyMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	clone := make(map[string]any, len(value))
	for key, item := range value {
		clone[key] = item
	}
	return clone
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return map[string]string{}
	}
	clone := make(map[string]string, len(value))
	for key, item := range value {
		clone[key] = item
	}
	return clone
}

func nullIfEmpty(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
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

func truncateString(value string, limit int) string {
	if limit <= 0 {
		return strings.TrimSpace(value)
	}
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= limit {
		return trimmed
	}
	return trimmed[:limit]
}

func shouldRetryJob(attemptNumber int, maxAttempts int, responseStatus int, errorMessage string) bool {
	if maxAttempts <= 0 {
		maxAttempts = defaultRetryAttempts
	}
	if attemptNumber >= maxAttempts {
		return false
	}
	if responseStatus >= 400 && responseStatus < 500 && responseStatus != 408 && responseStatus != 429 {
		return false
	}
	return strings.TrimSpace(errorMessage) != "" || responseStatus >= 500 || responseStatus == 408 || responseStatus == 429 || responseStatus == 0
}

func computeRetryDelay(attemptNumber int, baseDelaySeconds int, maxDelaySeconds int) time.Duration {
	base := time.Duration(clampInt(baseDelaySeconds, 1, 3600, defaultRetryBaseSecs)) * time.Second
	maxDelay := time.Duration(clampInt(maxDelaySeconds, 1, 86400, defaultRetryMaxSecs)) * time.Second
	if base > maxDelay {
		base = maxDelay
	}
	delay := base
	for step := 1; step < attemptNumber; step++ {
		delay *= 2
		if delay >= maxDelay {
			return maxDelay
		}
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}
