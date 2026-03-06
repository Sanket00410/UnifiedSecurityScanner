package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"unifiedsecurityscanner/control-plane/internal/models"
)

const (
	ExecutionControlEmergencyStop   = "emergency_stop_active"
	ExecutionControlMaintenanceStop = "maintenance_window_active"
)

type ExecutionControlViolationError struct {
	Code       string
	Message    string
	TenantID   string
	Reason     string
	WindowID   string
	WindowName string
}

func (e *ExecutionControlViolationError) Error() string {
	if e == nil {
		return "execution controls violation"
	}
	if strings.TrimSpace(e.Message) != "" {
		return e.Message
	}
	switch strings.TrimSpace(strings.ToLower(e.Code)) {
	case ExecutionControlEmergencyStop:
		return "tenant emergency stop is active"
	case ExecutionControlMaintenanceStop:
		return "tenant maintenance window is active"
	default:
		return "execution controls violation"
	}
}

func (s *Store) GetTenantExecutionControlsForTenant(ctx context.Context, tenantID string) (models.TenantExecutionControls, error) {
	return s.loadTenantExecutionControls(ctx, strings.TrimSpace(tenantID))
}

func (s *Store) UpdateTenantExecutionControlsForTenant(ctx context.Context, tenantID string, actor string, request models.UpdateTenantExecutionControlsRequest) (models.TenantExecutionControls, error) {
	tenantID = strings.TrimSpace(tenantID)
	actor = strings.TrimSpace(actor)
	now := time.Now().UTC()

	current, err := s.loadTenantExecutionControls(ctx, tenantID)
	if err != nil {
		return models.TenantExecutionControls{}, err
	}

	next := current
	next.TenantID = tenantID
	next.UpdatedAt = now
	if actor != "" {
		next.UpdatedBy = actor
	}

	if request.EmergencyStopEnabled != nil {
		next.EmergencyStopEnabled = *request.EmergencyStopEnabled
		if !next.EmergencyStopEnabled && request.EmergencyStopReason == nil {
			next.EmergencyStopReason = ""
		}
	}
	if request.EmergencyStopReason != nil {
		next.EmergencyStopReason = strings.TrimSpace(*request.EmergencyStopReason)
	}
	if next.EmergencyStopEnabled && next.EmergencyStopReason == "" {
		next.EmergencyStopReason = "manually enabled"
	}

	if request.MaintenanceWindows != nil {
		windows, err := sanitizeMaintenanceWindows(*request.MaintenanceWindows)
		if err != nil {
			return models.TenantExecutionControls{}, err
		}
		next.MaintenanceWindows = windows
	}

	if next.UpdatedBy == "" {
		next.UpdatedBy = "system"
	}

	windowsJSON, err := json.Marshal(next.MaintenanceWindows)
	if err != nil {
		return models.TenantExecutionControls{}, fmt.Errorf("marshal maintenance windows: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO tenant_execution_controls (
			tenant_id, emergency_stop_enabled, emergency_stop_reason, maintenance_windows_json, updated_by, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6
		)
		ON CONFLICT (tenant_id) DO UPDATE SET
			emergency_stop_enabled = EXCLUDED.emergency_stop_enabled,
			emergency_stop_reason = EXCLUDED.emergency_stop_reason,
			maintenance_windows_json = EXCLUDED.maintenance_windows_json,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
	`, next.TenantID, next.EmergencyStopEnabled, next.EmergencyStopReason, windowsJSON, next.UpdatedBy, next.UpdatedAt)
	if err != nil {
		return models.TenantExecutionControls{}, fmt.Errorf("upsert tenant execution controls: %w", err)
	}

	_ = s.publishPlatformEvent(ctx, models.PlatformEvent{
		TenantID:      tenantID,
		EventType:     "tenant_execution_controls.updated",
		SourceService: "control-plane",
		AggregateType: "tenant",
		AggregateID:   tenantID,
		Payload: map[string]any{
			"emergency_stop_enabled": next.EmergencyStopEnabled,
			"maintenance_windows":    len(next.MaintenanceWindows),
			"updated_by":             next.UpdatedBy,
		},
		CreatedAt: now,
	})

	return next, nil
}

func (s *Store) loadTenantExecutionControls(ctx context.Context, tenantID string) (models.TenantExecutionControls, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, emergency_stop_enabled, emergency_stop_reason, maintenance_windows_json, updated_by, updated_at
		FROM tenant_execution_controls
		WHERE tenant_id = $1
	`, tenantID)
	return scanTenantExecutionControls(row, tenantID)
}

func loadTenantExecutionControlsTx(ctx context.Context, tx pgx.Tx, tenantID string) (models.TenantExecutionControls, error) {
	row := tx.QueryRow(ctx, `
		SELECT tenant_id, emergency_stop_enabled, emergency_stop_reason, maintenance_windows_json, updated_by, updated_at
		FROM tenant_execution_controls
		WHERE tenant_id = $1
	`, tenantID)
	return scanTenantExecutionControls(row, tenantID)
}

func scanTenantExecutionControls(row interface{ Scan(dest ...any) error }, tenantID string) (models.TenantExecutionControls, error) {
	var (
		item        models.TenantExecutionControls
		windowsJSON []byte
	)

	err := row.Scan(
		&item.TenantID,
		&item.EmergencyStopEnabled,
		&item.EmergencyStopReason,
		&windowsJSON,
		&item.UpdatedBy,
		&item.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.TenantExecutionControls{
				TenantID:           strings.TrimSpace(tenantID),
				MaintenanceWindows: []models.MaintenanceWindow{},
			}, nil
		}
		return models.TenantExecutionControls{}, err
	}

	if len(windowsJSON) > 0 {
		if err := json.Unmarshal(windowsJSON, &item.MaintenanceWindows); err != nil {
			return models.TenantExecutionControls{}, fmt.Errorf("decode maintenance windows: %w", err)
		}
	}
	if item.MaintenanceWindows == nil {
		item.MaintenanceWindows = []models.MaintenanceWindow{}
	}

	return item, nil
}

func checkTenantExecutionControlsTx(ctx context.Context, tx pgx.Tx, tenantID string, targetKind string, now time.Time) (*ExecutionControlViolationError, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil
	}

	controls, err := loadTenantExecutionControlsTx(ctx, tx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load tenant execution controls tx: %w", err)
	}

	return evaluateExecutionControlViolation(controls, targetKind, now), nil
}

func evaluateExecutionControlViolation(controls models.TenantExecutionControls, targetKind string, now time.Time) *ExecutionControlViolationError {
	if controls.EmergencyStopEnabled {
		message := "tenant emergency stop is active"
		if reason := strings.TrimSpace(controls.EmergencyStopReason); reason != "" {
			message = fmt.Sprintf("tenant emergency stop is active: %s", reason)
		}
		return &ExecutionControlViolationError{
			Code:     ExecutionControlEmergencyStop,
			Message:  message,
			TenantID: controls.TenantID,
			Reason:   strings.TrimSpace(controls.EmergencyStopReason),
		}
	}

	for _, window := range controls.MaintenanceWindows {
		if maintenanceWindowApplies(window, targetKind, now) {
			message := "tenant maintenance window is active"
			if name := strings.TrimSpace(window.Name); name != "" {
				message = fmt.Sprintf("tenant maintenance window %q is active", name)
			}
			return &ExecutionControlViolationError{
				Code:       ExecutionControlMaintenanceStop,
				Message:    message,
				TenantID:   controls.TenantID,
				Reason:     strings.TrimSpace(window.Reason),
				WindowID:   strings.TrimSpace(window.ID),
				WindowName: strings.TrimSpace(window.Name),
			}
		}
	}

	return nil
}

func sanitizeMaintenanceWindows(windows []models.MaintenanceWindow) ([]models.MaintenanceWindow, error) {
	if len(windows) == 0 {
		return []models.MaintenanceWindow{}, nil
	}

	out := make([]models.MaintenanceWindow, 0, len(windows))
	for index, item := range windows {
		window := item
		window.ID = strings.TrimSpace(window.ID)
		if window.ID == "" {
			window.ID = fmt.Sprintf("window-%d", index+1)
		}
		window.Name = strings.TrimSpace(window.Name)
		window.Reason = strings.TrimSpace(window.Reason)

		timezone := strings.TrimSpace(window.Timezone)
		if timezone == "" {
			timezone = "UTC"
		}
		if _, err := time.LoadLocation(timezone); err != nil {
			return nil, fmt.Errorf("maintenance window %s has invalid timezone %q", window.ID, timezone)
		}
		window.Timezone = timezone

		if window.StartHour < 0 || window.StartHour > 23 {
			return nil, fmt.Errorf("maintenance window %s start_hour must be between 0 and 23", window.ID)
		}
		if window.EndHour < 0 || window.EndHour > 23 {
			return nil, fmt.Errorf("maintenance window %s end_hour must be between 0 and 23", window.ID)
		}
		if window.StartMinute < 0 || window.StartMinute > 59 {
			return nil, fmt.Errorf("maintenance window %s start_minute must be between 0 and 59", window.ID)
		}
		if window.EndMinute < 0 || window.EndMinute > 59 {
			return nil, fmt.Errorf("maintenance window %s end_minute must be between 0 and 59", window.ID)
		}

		normalizedDays, err := normalizeMaintenanceDays(window.Days)
		if err != nil {
			return nil, fmt.Errorf("maintenance window %s: %w", window.ID, err)
		}
		window.Days = normalizedDays

		window.TargetKinds = normalizeStringList(window.TargetKinds)
		out = append(out, window)
	}
	return out, nil
}

func normalizeMaintenanceDays(days []string) ([]string, error) {
	if len(days) == 0 {
		return []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}, nil
	}

	out := make([]string, 0, len(days))
	for _, raw := range days {
		day, ok := normalizeMaintenanceDay(raw)
		if !ok {
			return nil, fmt.Errorf("invalid day %q; use sun..sat", raw)
		}
		if slices.Contains(out, day) {
			continue
		}
		out = append(out, day)
	}
	return out, nil
}

func normalizeMaintenanceDay(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sun", "sunday":
		return "sun", true
	case "mon", "monday":
		return "mon", true
	case "tue", "tues", "tuesday":
		return "tue", true
	case "wed", "wednesday":
		return "wed", true
	case "thu", "thur", "thurs", "thursday":
		return "thu", true
	case "fri", "friday":
		return "fri", true
	case "sat", "saturday":
		return "sat", true
	default:
		return "", false
	}
}

func weekdayCode(day time.Weekday) string {
	switch day {
	case time.Sunday:
		return "sun"
	case time.Monday:
		return "mon"
	case time.Tuesday:
		return "tue"
	case time.Wednesday:
		return "wed"
	case time.Thursday:
		return "thu"
	case time.Friday:
		return "fri"
	case time.Saturday:
		return "sat"
	default:
		return ""
	}
}

func maintenanceWindowApplies(window models.MaintenanceWindow, targetKind string, now time.Time) bool {
	if !maintenanceWindowAllowsTargetKind(window.TargetKinds, targetKind) {
		return false
	}

	location, err := time.LoadLocation(strings.TrimSpace(window.Timezone))
	if err != nil {
		location = time.UTC
	}

	localNow := now.In(location)
	nowMinute := localNow.Hour()*60 + localNow.Minute()
	startMinute := window.StartHour*60 + window.StartMinute
	endMinute := window.EndHour*60 + window.EndMinute
	currentDay := weekdayCode(localNow.Weekday())
	previousDay := weekdayCode((localNow.Weekday() + 6) % 7)

	days := window.Days
	if len(days) == 0 {
		days = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
	}

	for _, day := range days {
		day = strings.ToLower(strings.TrimSpace(day))
		switch {
		case startMinute == endMinute:
			if day == currentDay {
				return true
			}
		case startMinute < endMinute:
			if day == currentDay && nowMinute >= startMinute && nowMinute < endMinute {
				return true
			}
		default:
			if day == currentDay && nowMinute >= startMinute {
				return true
			}
			if day == previousDay && nowMinute < endMinute {
				return true
			}
		}
	}

	return false
}

func maintenanceWindowAllowsTargetKind(targetKinds []string, targetKind string) bool {
	if len(targetKinds) == 0 {
		return true
	}

	targetKind = strings.ToLower(strings.TrimSpace(targetKind))
	for _, item := range targetKinds {
		candidate := strings.ToLower(strings.TrimSpace(item))
		if candidate == "" {
			continue
		}
		if candidate == "*" || candidate == "all" || candidate == targetKind {
			return true
		}
	}
	return false
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" || slices.Contains(out, normalized) {
			continue
		}
		out = append(out, normalized)
	}
	return out
}
