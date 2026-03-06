package models

import "time"

type MaintenanceWindow struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Timezone    string   `json:"timezone,omitempty"`
	Days        []string `json:"days,omitempty"`
	StartHour   int      `json:"start_hour"`
	StartMinute int      `json:"start_minute,omitempty"`
	EndHour     int      `json:"end_hour"`
	EndMinute   int      `json:"end_minute,omitempty"`
	TargetKinds []string `json:"target_kinds,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

type TenantExecutionControls struct {
	TenantID             string              `json:"tenant_id"`
	EmergencyStopEnabled bool                `json:"emergency_stop_enabled"`
	EmergencyStopReason  string              `json:"emergency_stop_reason,omitempty"`
	MaintenanceWindows   []MaintenanceWindow `json:"maintenance_windows,omitempty"`
	UpdatedBy            string              `json:"updated_by,omitempty"`
	UpdatedAt            time.Time           `json:"updated_at"`
}

type UpdateTenantExecutionControlsRequest struct {
	EmergencyStopEnabled *bool                `json:"emergency_stop_enabled"`
	EmergencyStopReason  *string              `json:"emergency_stop_reason"`
	MaintenanceWindows   *[]MaintenanceWindow `json:"maintenance_windows"`
}
